// SPDX-License-Identifier: MPL-2.0

use super::SyscallReturn;
use crate::{
    fs::file::file_table::{RawFileDesc, get_file_fast},
    prelude::*,
    util::net::read_socket_addr_from_user,
};

pub fn sys_connect(
    sockfd: RawFileDesc,
    sockaddr_ptr: Vaddr,
    addr_len: u32,
    ctx: &Context,
) -> Result<SyscallReturn> {
    let socket_addr = read_socket_addr_from_user(sockaddr_ptr, addr_len as _)?;
    debug!("fd = {sockfd}, socket_addr = {socket_addr:?}");

    // astromac MAC (network): a tenant-labeled subject connecting to a
    // differently-labeled IPv4 endpoint may be denied. No-op unless some IP is
    // labeled and the subject is a non-zero tenant (so every unmodified node is
    // unaffected).
    if crate::security::lsm::astromac::has_ip_labels()
        && let crate::net::socket::util::SocketAddr::IPv4(addr, _) = &socket_addr
    {
        let subject_tenant = ctx.posix_thread.mac_tenant();
        if subject_tenant != 0 {
            let dst = u32::from_be_bytes(addr.octets());
            crate::security::lsm::hooks::on_socket_connect(
                &crate::security::lsm::hooks::SocketConnectContext::new(subject_tenant, dst),
            )?;
        }
    }

    let mut file_table = ctx.thread_local.borrow_file_table_mut();
    let file = get_file_fast!(&mut file_table, sockfd.try_into()?);
    let socket = file.as_socket_or_err()?;

    socket
        .connect(socket_addr)
        .map_err(|err| match err.error() {
            // FIXME: `connect` should not be restarted if a timeout has been set on the socket using `setsockopt`.
            Errno::EINTR => Error::new(Errno::ERESTARTSYS),
            _ => err,
        })?;

    Ok(SyscallReturn::Return(0))
}
