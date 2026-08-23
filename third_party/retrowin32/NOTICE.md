# retrowin32 attribution

Portions of `src/win32_host.rs` and their integration in
`src/x86_filter.rs` use architecture and selected implementation ideas from
retrowin32.

- Upstream project: <https://github.com/evmar/retrowin32> 
- Upstream author/project maintainer: Evan Martin and retrowin32 contributors
- Upstream license: Apache License 2.0

The main upstream areas consulted were:

- `win32/src/shims.rs` and Unicorn shim dispatch
- `win32/system/src/dll.rs` and loader/export tables
- `win32/system/src/heap.rs`
- `win32/dll/kernel32/src/{loader,memory,nls,state,thread}.rs`

retrowin32 did not provide a repository `NOTICE` file at the audited revision.
Its complete Apache License 2.0 text is reproduced in
`LICENSE-APACHE-2.0.txt` beside this notice.
