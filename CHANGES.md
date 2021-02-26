# Release notes
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## 0.2.3
### Features
- None

### Fixes
- Allow `ebpf_maps:close/1` to also close the underlying eBPF map of an `ebpf_maps:iterator()`.
  Before this change, when calling `Iterator = ebpf_maps:iterator(Map)`, `Map` had to be kept around
  in order to close the underlying eBPF map when `Iterator` is no longer needed, e.g.:
  ```erlang
  Map = ebpf_maps:new(...),
  Iterator = ebpf_maps:iterator(Map),
  % use Iterator
  ok = ebpf_maps:close(Map).
  ```
  With this fix its possible to pass `Iterator` around and forget about `Map`:
  ```erlang
  foo() ->
    Map = ebpf_maps:new(...),
    Iterator = ebpf_maps:iterator(Map),
    consume_iterator(Iterator).

  consume_iterator(Iterator) ->
    ...
    ok = ebpf_maps:close(Iterator).
  ```

### Breaking changes
- None

## 0.2.2
### Features
- Add `ebpf_maps:take/2`

### Fixes
- Minor documentation fixes

### Breaking changes
- None


## 0.2.1
### Features
- Add `ebpf_kern:return/1`
- Add `ebpf_kern:branch/5`

### Fixes
- None

### Breaking changes
- None

## 0.2.0
Initial release

## 0.1.x
Experiments
