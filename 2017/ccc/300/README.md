The [challenge](300) is simple to understand. In the BSS there is a 10-pointers array `allocs`. We can execute one of the following options:
1. `allocs[slot] = malloc(0x300);`
2. `read(0, allocs[slot], 0x300);`
3. `write(1, allocs[slot], strlen(slot));`
4. `free(allocs[slot]);`
5. Make the program exit.

We can quickly get a leak of `heap` and `libc` pointers by freeing two non-consecutive chunks that don't coalesce with the wilderness and read their `fd` pointers. The first will point to the second - `heap` pointer and the second will point to the `unsorted_bin` which resides in `libc`'s data segment.

Moving on, we see we can not only read freed chunks in the unsorted bin but also overwrite them leads to the conclusion that _unsorted_bin attack_ is the most plausible approach. What is not clear is how to hijack the flow using this attack. My solution was to use the _House of Orange_ which overwrites `_IO_list_all` and hijacks the flow when jumping to the `__overflow` method invoked in `_IO_flush_all_lockp`.

Quick re-cap: _House of Orange_ & _unsorted_bin attack_.
First step is to abuse `malloc` when sorting the unsorted bin. The implementation does an unsafe unlinking from the back of the list:
```
3503   for (;; )
3504     {
3505       int iters = 0;
3506       while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
3507         {
3508           bck = victim->bk;
...
3513           size = chunksize (victim);
... 
3551           /* remove from unsorted list */
3552           unsorted_chunks (av)->bk = bck;
3553           bck->fd = unsorted_chunks (av);
3554 
3555           /* Take now instead of binning if exact fit */
3556 
3557           if (size == nb)
3558             {
...
3563               void *p = chunk2mem (victim);
3564               alloc_perturb (p, bytes);
3565               return p;
3566             }
3567 
3568           /* place chunk in bin */
3569 
3570           if (in_smallbin_range (size))
3571             {
3572               victim_index = smallbin_index (size);
3573               bck = bin_at (av, victim_index);
3574               fwd = bck->fd;
3575             }
...
3625           victim->bk = bck;
3626           victim->fd = fwd;
3627           fwd->bk = victim;
3628           bck->fd = victim;
...
3633         }
```
The unsafe unlinking happens in line 3553. This line enables an attacker controlling the `bk` pointer of a chunk in the unsorted bin to overwrite any data with the `unsorted_chunks(main_arena)` (which is 0x10 bytes before `main_arena.bins`). If the size of that controlled chunk matches the requested size (line 3557) the code will return that chunk immediately.

The _House of Orange_ uses this attack and overwrites `_IO_list_all`. Then jumps to `_IO_flush_all_lockp` which is invoked in program's termination. Here is the relevant code:
```
 778   fp = (_IO_FILE *) _IO_list_all;
 779   while (fp != NULL)
 780     {
...
 785       if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
 786 #if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
 787        || (_IO_vtable_offset (fp) == 0
 788            && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
 789                     > fp->_wide_data->_IO_write_base))
 790 #endif
 791        )
 792       && _IO_OVERFLOW (fp, EOF) == EOF)
 793     result = EOF;
...
 806     fp = fp->_chain;
 807     }
```
In the first iteration of the loop we don't have too much control, as the fields pointed by `fp` are  the `main_arena`'s bins (the data following the `unsorted_chunks`). We can only make them either point to the `libc` data (empty bin) or to the heap (if the bin has some freed chunks). So our objective in the first iteration is to avoid line 792 - the indirect invocation of the `__overflow` method. This actually happens automatically as `fp->_IO_write_ptr` and `fp->_IO_write_base` contain the same value (both are head and tail of the same bin). Then, in line 806 we de-reference `fp->_chain`, which happens to coincide with 0x60-size bin. So we need to populate that bin with a pointer to our controlled data on the heap. We do it in two steps: first, we overwrite a chunk in the unsorted bin to point to our controlled data on the heap and make an allocation. Now, the `bk` pointer of the `unsorted_chunks` points to our controlled data. We craft this data to look like a chunk of size 0x61 with a `bk` pointer pointing to a crafted chunk with size 0x311 and `bk` that points to `_IO_list_all`.  This will cause the `fp` in the second iteration to point to our controlled data, where we can satisfy the conditions to invoke the `__overflow` method using our controlled `vtable` pointer (if you unfold all these awful macros you get something like `fp->_vtable.__overflow(fp, EOF)`).

The exploit we described so far is perfect for  glibc 2.23. However, in glibc version 2.24 a new mitigation was added: `IO_validate_vtable` function which ensures that the `FILE` object's `vtable` points somewhere within the `__libc_IO_vtables` section (it's worth reading the implementation, there are nice gems in there). So, this restricts us a little bit. But don't worry! There are plenty of functions pointed in the `__libc_IO_vtables` section and one of them is perfect for our needs: `_IO_wstr_finish`.
Here is the code:
```
325 void
326 _IO_wstr_finish (_IO_FILE *fp, int dummy)
327 {
328   if (fp->_wide_data->_IO_buf_base && !(fp->_flags2 & _IO_FLAGS2_USER_WBUF))
329     (((_IO_strfile *) fp)->_s._free_buffer) (fp->_wide_data->_IO_buf_base);
```
As we control `fp`, we can quite easily satisfy the condition in line 328 and hijack the flow - faking the `_free_buffer` function pointer.
A `one_gadget` is all it takes from here to get to `system("/bin/sh")`.

You can read the [full exploit here](x.py).
