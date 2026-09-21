#![no_main]
#![no_std]
extern crate alloc;
#[global_allocator]
static ALLOCATOR: uefi::allocator::Allocator = uefi::allocator::Allocator;

use alloc::format;
use alloc::string::{String, ToString};
use log::{debug, info, LevelFilter};
use uefi::prelude::*;
use uefi::{guid, CStr16};
use uefi::runtime::{self, ResetType, VariableAttributes, VariableVendor};
use uefi::Status;
use alloc::vec::Vec;
use uefi::boot;
use uefi::proto::network::ip4config2::Ip4Config2;
use uefi::proto::network::pxe::{BaseCode, DhcpV4Packet};


// This will:
// 1. Set up the network interface
// 2. Request DHCP information to find the PXE server
// 3. Enroll keys if in setup mode
// 4. Add an HTTP boot entry to the UEFI boot manager
// 5. Reboot into the Kairos installer
// 6. If no DHCP server is found, stall for 5 seconds and reset the system
// 7. If the HTTP boot entry cannot be added, stall for 10 seconds and reset the system
// 8. If the key enrollment fails, stall for 5 seconds and reset the system
// 9. If the HTTP download fails, stall for 5 seconds and reset the system
// 10. If the PK, KEK, or DB enrollment fails, stall for 5 seconds and reset the system
// 11. If the HTTP download is incomplete, warn the user
// 12. If the HTTP download fails, warn the user

// Getting the "proper" server to get the keys and add the entry is a bit iffy.
// We assume that the PXE server is the one that its serving everything as we expect Auroraboot
// to be the one that is serving the keys and efis. 
// So we launch a dhcp ack to get the ipxe server, and then we use that to get the keys and the server for
// the HTTP boot entry.
// Main problem with this approach is that we leave a Kairos installer entry in there, something that we
// can probably fix by removing the entry from userspace after the installation is done.
// Alos we try to set it up as the highest entry in the boot order, so it should be the first one to be selected.
// but not all firmwares are the same so we don't know if that will work.


#[entry]
unsafe fn main() -> Status {
    uefi::helpers::init().unwrap();
    log::set_max_level(LevelFilter::Info);
    
    if !is_setup_mode() {
        info!("Not in setup mode, resetting...");
        boot::stall(5_000_000);
        runtime::reset(ResetType::COLD, Status::ABORTED, None);
    }

    // Setup network interface and get NIC handle
    let nic_handle = match setup_network_interface() {
        Ok(h) => h,
        Err(e) => {
            info!("Failed to set up network interface: {:?}", e);
            boot::stall(5_000_000);
            runtime::reset(ResetType::COLD, Status::ABORTED, None);
        }
    };
    
    info!("Booting key enroller...");

    // Try to request DHCP information to find PXE server info
    let server = match request_dhcp_info() {
        Some(server) => {
            info!("Next boot server (from DHCP): {}", server);
            server
        },
        None => {
            info!("No next boot server found in DHCP options, cant continue!");
            boot::stall(5_000_000);
            runtime::reset(ResetType::COLD, Status::ABORTED, None);
        },
    };

    if is_setup_mode() {
        info!("Setup Mode detected. Enrolling keys...");
        if let Err(e) = enroll_all_keys(&server) {
            info!("Key enrollment failed: {:?}", e);
        } else {
            info!("Keys enrolled.");
        }
    } else {
        info!("Not in setup mode, skipping key enrollment");
    }

    // Add HTTP boot entry using the NIC device path
    add_http_boot_entry(
        nic_handle,
        format!("http://{}/kairos.iso", server).as_str(),
        "Kairos",
    ).unwrap_or_else(|e| {
        info!("Failed to add HTTP boot entry: {:?}", e);
        boot::stall(10_000_000);
        runtime::reset(ResetType::COLD, Status::ABORTED, None);
    });

    // Store the PXE boot URL in the PXEBoot variable so it can be used in userspace by immucore or whatever
    set_pxeboot_efivar(format!("http://{}/kairos.iso", server).as_str());
    
    info!("Boot entry added and keys enrolled. Rebooting into Kairos installer...");
    boot::stall(5_000_000);
    runtime::reset(ResetType::COLD, Status::ABORTED, None);
}


fn is_setup_mode() -> bool {
    let mut name_buf = [0u16; 16];
    let name = CStr16::from_str_with_buf("SetupMode", &mut name_buf).unwrap();
    let mut buffer = [0u8; 1];

    match runtime::get_variable(name, &VariableVendor::GLOBAL_VARIABLE, &mut buffer) {
        Ok((data, _)) => data.len() == 1 && data[0] == 1,
        _ => false,
    }
}

fn enroll_all_keys(server: &str) -> Result<(), Status> {
    let base_url = format!("http://{}/", server);
    let pk_url = format!("{}PK.auth", base_url);
    let kek_url = format!("{}KEK.auth", base_url);
    let db_url = format!("{}DB.auth", base_url);

    info!("Downloading PK from {}...", pk_url);
    let pk = match http_download(&pk_url) {
        Ok(data) => data,
        Err(e) => {
            info!("Failed to download PK: {:?}. Stalling for 5 seconds before reset.", e);
            boot::stall(5_000_000);
            runtime::reset(ResetType::COLD, Status::ABORTED, None);
        }
    };
    info!("Downloading KEK from {}...", kek_url);
    let kek = match http_download(&kek_url) {
        Ok(data) => data,
        Err(e) => {
            info!("Failed to download KEK: {:?}. Stalling for 5 seconds before reset.", e);
            boot::stall(5_000_000);
            runtime::reset(ResetType::COLD, Status::ABORTED, None);
        }
    };
    info!("Downloading db from {}...", db_url);
    // TODO: Fall back to db instead of DB??
    let db = match http_download(&db_url) {
        Ok(data) => data,
        Err(e) => {
            info!("Failed to download DB: {:?}. Stalling for 5 seconds before reset.", e);
            boot::stall(5_000_000);
            runtime::reset(ResetType::COLD, Status::ABORTED, None);
        }
    };

    enroll_key("db", &db)?;
    enroll_key("KEK", &kek)?;
    enroll_key("PK", &pk)?;
    Ok(())
}

fn enroll_key(name: &str, data: &[u8]) -> Result<(), Status> {
    let mut binding = [0u16; 16];
    let name_utf16 = CStr16::from_str_with_buf(name, &mut binding).unwrap();

    let vendor = match name {
        "db" | "dbx" => &VariableVendor::IMAGE_SECURITY_DATABASE,
        "PK" | "KEK" => &VariableVendor::GLOBAL_VARIABLE,
        _ => return Err(Status::INVALID_PARAMETER),
    };

    info!("Setting var '{}', vendor: {:?}, size: {}", name, vendor, data.len());

    // Log the first few and last few bytes of the data for debugging
    if !data.is_empty() {
        let prefix_len = core::cmp::min(16, data.len());
        let suffix_start = if data.len() > 16 { data.len() - 16 } else { 0 };

        let mut prefix_str = String::new();
        for byte in &data[0..prefix_len] {
            prefix_str.push_str(&format!("{:02x} ", byte));
        }

        let mut suffix_str = String::new();
        if data.len() > 16 {
            suffix_str.push_str("... ");
            for byte in &data[suffix_start..] {
                suffix_str.push_str(&format!("{:02x} ", byte));
            }
        }
    }

    let result = runtime::set_variable(
        name_utf16,
        vendor,
        VariableAttributes::NON_VOLATILE
            | VariableAttributes::BOOTSERVICE_ACCESS
            | VariableAttributes::RUNTIME_ACCESS
            | VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
        data,
    );

    if let Err(ref e) = result {
        info!("set_variable for '{}' failed with status: {:?}", name, e.status());
    }

    result.map_err(|e| e.status())
}

fn setup_network_interface() -> Result<uefi::Handle, Status> {
    info!("Setting up network interface...");
    let nic_handle = boot::get_handle_for_protocol::<uefi::proto::network::http::HttpBinding>()
        .map_err(|e| e.status())?;

    let mut ip4 = Ip4Config2::new(nic_handle)
        .map_err(|e| e.status())?;
    ip4.ifup(false).map_err(|e| e.status())?;

    // Print IP configuration after DHCP
    if let Ok(info) = ip4.get_interface_info() {
        let hw = &info.hw_addr;
        log::info!(
            "IP config: addr {}.{}.{}.{}, mask {}.{}.{}.{}, hw_addr {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            info.station_addr.0[0], info.station_addr.0[1], info.station_addr.0[2], info.station_addr.0[3],
            info.subnet_mask.0[0], info.subnet_mask.0[1], info.subnet_mask.0[2], info.subnet_mask.0[3],
            hw.0[0], hw.0[1], hw.0[2], hw.0[3], hw.0[4], hw.0[5]
        );
    }
    Ok(nic_handle)
}

fn http_download(url: &str) -> Result<Vec<u8>, Status> {
    info!("Starting HTTP download from {}", url);
    let nic_handle = boot::get_handle_for_protocol::<uefi::proto::network::http::HttpBinding>()
        .map_err(|e| e.status())?;

    let mut http = uefi::proto::network::http::HttpHelper::new(nic_handle)
        .map_err(|e| e.status())?;
    http.configure().map_err(|e| e.status())?;

    // Send the HTTP GET request
    http.request_get(url).map_err(|e| e.status())?;

    // Get the first part of the response (includes headers and initial body chunk)
    let resp = http.response_first(true).map_err(|e| {
        info!("HTTP response_first failed: {:?}", e);
        e.status()
    })?;

    // Check HTTP status code (3 is STATUS_200_OK in the HttpStatusCode enum)
    if resp.status.0 != 3 { // STATUS_200_OK
        info!("HTTP GET failed: non-success status code {:?}", resp.status);
        return Err(Status::PROTOCOL_ERROR);
    }

    // Log headers and look for Content-Length
    let mut content_length: Option<usize> = None;
    for (name, value) in &resp.headers {
        if name.to_lowercase() == "content-length" {
            if let Ok(len) = value.parse::<usize>() {
                content_length = Some(len);
            }
        }
    }

    // Start with the initial body chunk
    let mut full_body = resp.body;

    // Try to get more data until we have the complete file or no more data is available
    let mut chunk_count = 1;
    loop {
        // Try to get more body data
        match http.response_more() {
            Ok(more_data) => {
                if more_data.is_empty() {
                    break;
                }

                chunk_count += 1;
                full_body.extend_from_slice(&more_data);

                // Log progress if Content-Length is known
                if let Some(total) = content_length {
                    debug!("Progress: {}/{} bytes ({:.1}%)",
                          full_body.len(), total,
                          (full_body.len() as f32 / total as f32) * 100.0);

                    // If we've received all the data, we're done
                    if full_body.len() >= total {
                        debug!("Download complete, received all {} bytes", full_body.len());
                        break;
                    }
                }
            },
            Err(e) => {
                // NOT_FOUND typically means no more data is available
                if e.status() == Status::NOT_FOUND {
                    debug!("No more data available");
                } else {
                    info!("Error fetching additional data: {:?}", e);
                }
                break;
            }
        }

        // Safety check to prevent infinite loops
        if chunk_count > 50 {
            debug!("Reached maximum chunk count, stopping download");
            break;
        }
    }

    if full_body.is_empty() {
        info!("HTTP GET succeeded but response body is empty");
        return Err(Status::NO_RESPONSE);
    }

    // Warn if download might be incomplete based on Content-Length
    if let Some(expected) = content_length {
        if full_body.len() < expected {
            info!("Warning: Incomplete download. Got {}/{} bytes", full_body.len(), expected);
        }
    }

    info!("HTTP download complete for {}. Total size: {} bytes in {} chunks", url, full_body.len(), chunk_count);

    Ok(full_body)
}

/// Sends a DHCP request to discover PXE server information and returns the next boot server address
/// from either Option 66 (TFTP server name) or the siaddr field in the DHCP header.
pub fn request_dhcp_info() -> Option<String> {
    info!("Sending DHCP discovery request to find PXE server...");

    // Try to find a network interface with the PXE Base Code protocol
    let nic_handle = match boot::get_handle_for_protocol::<BaseCode>() {
        Ok(handle) => {
            info!("Found NIC with PXE Base Code protocol: {:?}", handle);
            handle
        },
        Err(e) => {
            info!("No network interface with PXE Base Code protocol found: {:?}", e);
            return None;
        }
    };

    // Open the PXE protocol
    let mut pxe = match boot::open_protocol_exclusive::<BaseCode>(nic_handle) {
        Ok(p) => p,
        Err(e) => {
            info!("Failed to open PXE Base Code protocol: {:?}", e);
            return None;
        }
    };

    // Make sure the protocol is started
    if !pxe.mode().started() {
        info!("Starting PXE Base Code protocol");
        if let Err(e) = pxe.start(false) {
            info!("Failed to start PXE Base Code protocol: {:?}", e);
            return None;
        }
    }

    // Try to perform a DHCP discovery
    info!("Sending DHCP request...");
    if let Err(e) = pxe.dhcp(true) {
        info!("DHCP request failed: {:?}", e);
        return None;
    }

    // Successfully received DHCP response
    let mode = pxe.mode();

    if mode.dhcp_ack_received() {
        info!("Received DHCP ACK packet");
        let dhcp_packet = mode.dhcp_ack();
        let dhcp_v4 = AsRef::<DhcpV4Packet>::as_ref(dhcp_packet);

        // Log server information
        let server_addr = dhcp_v4.bootp_si_addr;
        info!("DHCP Server IP (siaddr): {}.{}.{}.{}",
             server_addr[0], server_addr[1],
             server_addr[2], server_addr[3]);

        let your_addr = dhcp_v4.bootp_yi_addr;
        info!("Your IP address: {}.{}.{}.{}",
             your_addr[0], your_addr[1],
             your_addr[2], your_addr[3]);

        // Check for Option 66 (TFTP Server Name) in DHCP options
        info!("Scanning DHCP options for Option 66 (TFTP server name)...");
        let dhcp_options = &dhcp_v4.dhcp_options;
        let mut i = 0;

        while i + 2 < dhcp_options.len() {
            let option_code = dhcp_options[i];
            if option_code == 255 { // End option
                break;
            }

            let option_len = dhcp_options[i+1] as usize;
            if i + 2 + option_len > dhcp_options.len() {
                break;
            }

            // Found Option 66 (TFTP Server Name)
            if option_code == 66 {
                if let Ok(server_name) = core::str::from_utf8(&dhcp_options[i+2..i+2+option_len]) {
                    info!("Found boot server name in Option 66: {}", server_name);
                    return Some(server_name.to_string());
                }
            }

            // Skip to next option
            i += option_len + 2;
        }

        // If Option 66 not found, use siaddr (next server IP) as the boot server
        if server_addr != [0, 0, 0, 0] {
            let ip = format!("{}.{}.{}.{}",
                server_addr[0], server_addr[1],
                server_addr[2], server_addr[3]);
            info!("Using DHCP server IP (siaddr) as boot server: {}", ip);
            return Some(ip);
        }

        // Check for PXE-specific information if siaddr is not set
        if mode.proxy_offer_received() {
            let proxy_offer = mode.proxy_offer();
            let proxy_v4 = AsRef::<DhcpV4Packet>::as_ref(proxy_offer);
            let proxy_addr = proxy_v4.bootp_si_addr;

            if proxy_addr != [0, 0, 0, 0] {
                let ip = format!("{}.{}.{}.{}",
                    proxy_addr[0], proxy_addr[1],
                    proxy_addr[2], proxy_addr[3]);
                info!("Using PXE Proxy Server as boot server: {}", ip);
                return Some(ip);
            }
        }

        if mode.pxe_reply_received() {
            let pxe_reply = mode.pxe_reply();
            let pxe_v4 = AsRef::<DhcpV4Packet>::as_ref(pxe_reply);
            let pxe_addr = pxe_v4.bootp_si_addr;

            if pxe_addr != [0, 0, 0, 0] {
                let ip = format!("{}.{}.{}.{}",
                    pxe_addr[0], pxe_addr[1],
                    pxe_addr[2], pxe_addr[3]);
                info!("Using PXE Reply Server as boot server: {}", ip);
                return Some(ip);
            }
        }
    } else {
        info!("No DHCP ACK received");
    }

    info!("Could not determine boot server from DHCP information");
    None
}

/// Reads the BootOrder variable and returns the boot numbers it holds.
///
/// BootOrder grows with the number of boot entries, so it is read into an
/// allocation of the size the firmware reports instead of a fixed buffer.
fn read_boot_order() -> Vec<u16> {
    let mut name_buf = [0u16; 12];
    let name = CStr16::from_str_with_buf("BootOrder", &mut name_buf).unwrap();
    match runtime::get_variable_boxed(name, &VariableVendor::GLOBAL_VARIABLE) {
        Ok((data, _)) => data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect(),
        Err(e) => {
            if e.status() != Status::NOT_FOUND {
                info!("Failed to read BootOrder: {:?}", e.status());
            }
            Vec::new()
        }
    }
}

/// Reports whether the Boot#### variable for `boot_num` is present.
///
/// get_variable answers BUFFER_TOO_SMALL for a variable that exists but does
/// not fit the buffer, so only NOT_FOUND means the slot is free. A load option
/// never fits in a probe buffer, so testing the call with is_ok() would report
/// every entry as absent.
fn boot_option_exists(boot_num: u16) -> bool {
    let boot_var = format!("Boot{:04X}", boot_num);
    let mut name_buf = [0u16; 12];
    let name = CStr16::from_str_with_buf(&boot_var, &mut name_buf).unwrap();
    match runtime::get_variable(name, &VariableVendor::GLOBAL_VARIABLE, &mut [0u8; 4]) {
        Ok(_) => true,
        Err(e) => e.status() != Status::NOT_FOUND,
    }
}

/// Adds a UEFI boot entry for HTTP(S) boot to the given URL with the provided description.
unsafe fn add_http_boot_entry(nic_handle: uefi::Handle, url: &str, description: &str) -> Result<(), Status> {
    use alloc::vec::Vec;
    use uefi::runtime::VariableVendor;
    use uefi::proto::device_path::DevicePath;
    use uefi::boot::{OpenProtocolParams, OpenProtocolAttributes};

    info!("Adding HTTP boot entry: {} -> {}", description, url);

    // 0. Check for existing entry with the same description
    for boot_num in read_boot_order() {
        let boot_var = format!("Boot{:04X}", boot_num);
        let mut name_buf = [0u16; 12];
        let name = CStr16::from_str_with_buf(&boot_var, &mut name_buf).unwrap();
        if let Ok((data, _)) = runtime::get_variable_boxed(name, &VariableVendor::GLOBAL_VARIABLE) {
            // EFI_LOAD_OPTION: attributes(4) + file_path_list_length(2) + description (utf16, null-terminated)
            if data.len() > 6 {
                let desc_start = 6;
                let mut desc_end = desc_start;
                while desc_end + 1 < data.len() {
                    if data[desc_end] == 0 && data[desc_end+1] == 0 { break; }
                    desc_end += 2;
                }
                let desc_bytes = &data[desc_start..desc_end];
                if let Ok(desc) = String::from_utf16(
                    &desc_bytes.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<_>>()
                ) {
                    info!("Boot entry {}: description='{}'", boot_var, desc);
                    if desc == description {
                        info!("Removing duplicate boot entry '{}' as {}", description, boot_var);
                        runtime::delete_variable(
                            name,
                            &VariableVendor::GLOBAL_VARIABLE,
                        ).map_err(|e| {
                            info!("Failed to delete boot entry '{}': {:?}", boot_var, e.status());
                            e.status()
                        })?;
                        // Do not break; continue to remove all duplicates
                    }
                }
            }
        }
    }

    // 1. Get NIC device path
    let dp_ptr = boot::open_protocol::<DevicePath>(
        OpenProtocolParams {
            handle: nic_handle,
            agent: boot::image_handle(),
            controller: None,
        },
        OpenProtocolAttributes::GetProtocol,
    ).map_err(|e| {
        info!("Failed to open DevicePath protocol: {:?}", e.status());
        e.status()
    })?;
    // SAFETY: ScopedProtocol derefs to &DevicePath
    let dp: &DevicePath = &*dp_ptr;
    // Find the length of the device path (walk until end node)
    let mut dp_bytes: Vec<u8> = Vec::new();
    let mut node_ptr = dp as *const DevicePath as *const u8;
    loop {
        let typ = unsafe { *node_ptr };
        let subtype = unsafe { *node_ptr.add(1) };
        let len = u16::from_le_bytes([unsafe { *node_ptr.add(2) }, unsafe { *node_ptr.add(3) }]) as usize;
        dp_bytes.extend_from_slice(unsafe { core::slice::from_raw_parts(node_ptr, len) });
        if typ == 0x7f && subtype == 0xff { break; }
        node_ptr = unsafe { node_ptr.add(len) };
    }

    // 3. Create IPv4 node for DHCP (required between MAC and URI nodes)
    let mut ipv4_node = Vec::with_capacity(27);
    ipv4_node.push(0x03);  // Messaging Device Path
    ipv4_node.push(0x0C);  // IPv4 Device Path
    ipv4_node.extend_from_slice(&(27u16).to_le_bytes());  // Length = 27 bytes
    // Local IPv4 address (0.0.0.0 = DHCP assigned)
    ipv4_node.extend_from_slice(&[0, 0, 0, 0]);
    // Remote IPv4 address (not used for HTTP boot)
    ipv4_node.extend_from_slice(&[0, 0, 0, 0]);
    // Local port (0 = dynamic)
    ipv4_node.extend_from_slice(&(0u16).to_le_bytes());
    // Remote port (0 = protocol default)
    ipv4_node.extend_from_slice(&(0u16).to_le_bytes());
    // Protocol (6 = TCP for HTTP)
    ipv4_node.extend_from_slice(&(6u16).to_le_bytes());
    // Static IP flag (0 = DHCP)
    ipv4_node.push(0);
    // Gateway IP address (0.0.0.0 = DHCP assigned)
    ipv4_node.extend_from_slice(&[0, 0, 0, 0]);
    // Subnet mask (0.0.0.0 = DHCP assigned)
    ipv4_node.extend_from_slice(&[0, 0, 0, 0]);

    // 4. Create URI device path node (UEFI HTTP boot: Type 0x03, Subtype 0x18)
    let uri_bytes = url.as_bytes();
    let uri_len = uri_bytes.len();
    let node_len = 4 + uri_len;
    let mut uri_node = Vec::with_capacity(node_len);
    uri_node.push(0x03); // Messaging Device Path
    uri_node.push(0x18); // URI Device Path
    uri_node.extend_from_slice(&(node_len as u16).to_le_bytes());
    uri_node.extend_from_slice(uri_bytes);
    let end_node = [0x7f, 0xff, 0x04, 0x00];

    // 5. Build full device path: NIC device path (excluding its end node) + URI node + end node
    // Remove the last 4 bytes (end node) from dp_bytes
    if dp_bytes.len() >= 4 {
        dp_bytes.truncate(dp_bytes.len() - 4);
    }
    let mut device_path: Vec<u8> = Vec::new();
    device_path.extend_from_slice(&dp_bytes);
    device_path.extend_from_slice(&ipv4_node);
    device_path.extend_from_slice(&uri_node);
    device_path.extend_from_slice(&end_node);

    // 4. Prepare the load option (see UEFI spec for EFI_LOAD_OPTION)
    // Attributes: ACTIVE (0x00000001)
    let attributes: u32 = 1;
    let description_utf16: Vec<u16> = description.encode_utf16().chain(core::iter::once(0)).collect();
    let file_path_list_length: u16 = device_path.len() as u16;
    let mut load_option: Vec<u8> = Vec::new();
    load_option.extend_from_slice(&attributes.to_le_bytes());
    load_option.extend_from_slice(&file_path_list_length.to_le_bytes());
    for w in &description_utf16 {
        load_option.extend_from_slice(&w.to_le_bytes());
    }
    load_option.extend_from_slice(&device_path);
    // No optional data

    // 5. Find a free Boot#### variable
    let mut boot_num = 0x0001u16;
    while boot_option_exists(boot_num) {
        if boot_num == 0xFFFF {
            info!("No free Boot#### variable is left");
            return Err(Status::OUT_OF_RESOURCES);
        }
        boot_num += 1;
    }
    let boot_var = format!("Boot{:04X}", boot_num);
    info!("Using boot variable: {}", boot_var);

    // 6. Set the Boot#### variable
    let mut name_buf = [0u16; 12];
    let name = CStr16::from_str_with_buf(&boot_var, &mut name_buf).unwrap();
    runtime::set_variable(
        name,
        &VariableVendor::GLOBAL_VARIABLE,
        VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS,
        &load_option,
    ).map_err(|e| {
        info!("Failed to set {}: {:?}", boot_var, e.status());
        e.status()
    })?;

    // 7. Add to BootOrder
    // Clean up BootOrder: remove any entries that were deleted above (i.e., with the same description)
    let mut binding = [0u16; 12];
    let bootorder_name = CStr16::from_str_with_buf("BootOrder", &mut binding).unwrap();
    let mut new_order: Vec<u16> = Vec::new();
    for existing in read_boot_order() {
        // Only keep if the variable still exists
        if existing != boot_num && boot_option_exists(existing) {
            new_order.push(existing);
        }
    }
    // Add the new entry first, so the firmware selects it on the next boot
    new_order.insert(0, boot_num);
    let new_order_bytes = unsafe {
        core::slice::from_raw_parts(new_order.as_ptr() as *const u8, new_order.len() * 2)
    };
    runtime::set_variable(
        bootorder_name,
        &VariableVendor::GLOBAL_VARIABLE,
        VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS,
        new_order_bytes,
    ).map_err(|e| {
        info!("Failed to update BootOrder: {:?}", e.status());
        e.status()
    })?;

    info!("HTTP boot entry added as {}", boot_var);
    Ok(())
}

fn set_pxeboot_efivar(value_str: &str) {
    let mut name_buf = [0u16; 16];
    let name = CStr16::from_str_with_buf("PXEBoot", &mut name_buf).unwrap();
    let guid = guid!("3c909ff1-80a9-5970-94f1-fefb255c88bd");
    let vendor = VariableVendor(guid);
    let value = value_str.as_bytes();
    match runtime::set_variable(
        name,
        &vendor, // Pass as &VariableVendor
        VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS,
        value,
    ) {
        Ok(_) => info!("Set PXEBoot efivar to {:?}", value_str),
        Err(e) => info!("Failed to set PXEBoot efivar: {:?}", e),
    }
}
