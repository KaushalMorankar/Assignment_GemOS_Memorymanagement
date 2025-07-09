#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>
#include </home/osws/Assignment4/gemOS/src/include/context.h>
#include </home/osws/Assignment4/gemOS/src/include/mmap.h>

/* 
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables 
 * */
#define PAGE_SIZE 4096
#define ul unsigned long 

#define MASK_9 (1<<9)-1
#define MASK_12 (1<<12)-1


//Create a new vm_area node
struct vm_area *create_vm_area_node(ul start, ul end, int prot)
{
    struct vm_area *dummy = (struct vm_area *)os_alloc(sizeof(struct vm_area));
    if (!dummy)
        return NULL;
    dummy->vm_start = start;
    dummy->vm_end = end;
    dummy->access_flags = prot;
    dummy->vm_next = NULL;
    stats->num_vm_area++;
    return dummy;
}

/*Why this flushes the TLB
CR3 on x86 holds the physical address of the root of the active page tables.
Any time CR3 is reloaded (even with the same value), the CPU discards all cached address‐translation entries (the TLB).
By reading CR3 and then writing it back unchanged, you force a full TLB invalidation without disturbing your page tables.
*/
void flush_tlbs(void)
{
    u64 cr3_value;
    asm volatile(
        "mov %%cr3, %0" //Move the value from CR3 into the variable
        : "=r"(cr3_value));

    asm volatile(
        "mov %0, %%rax\n\t" //Move the CR3 value into RAX
        "mov %%rax, %%cr3"  //Move the content of RAX into CR3
        :
        : "r"(cr3_value)
        : "eax");
}

static inline void flush_tlbs_page(unsigned long addr)
{
    /* invalidate only the TLB entry for virtual address ‘addr’ */
    asm volatile("invlpg (%0)"
                 :
                 : "r"(addr)
                 : "memory");
}

/**
 * mprotect System call Implementation.
 */
long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    if (!current || length <= 0) {
        return -EINVAL;
    }
    //u64 len_to_be_removed = page_aligned_len(length);
    u64 regstart=addr;
    u64 npages = (length + PAGE_SIZE - 1) / PAGE_SIZE;
    u64 regend = addr + npages * PAGE_SIZE;
    struct vm_area *vma=current->vm_area->vm_next; //pointing to the next node after dummy.
    struct vm_area *prev=current->vm_area;

    //Traverse the vm_area list to find overlapping regions
    while (vma != NULL)
    {
        struct vm_area *next_vma = vma->vm_next;
        //Continue till the vmarea is not found
        if (vma->vm_end < regstart || vma->vm_start > regend) 
        {
            prev=vma;
            vma = next_vma;
            continue;
        }
        //If vmarea is starting left of the one to protect
        if(vma->vm_start < regstart)
        {
            struct vm_area *left=create_vm_area_node(vma->vm_start,regstart,vma->access_flags);
            if(prev) 
            {    
                prev->vm_next=left;
            }
            vma->vm_start=regstart;
            left->vm_next=vma;
        }
        //If vmarea is ending right of the one to protect
        if (regend < vma->vm_end)
        {
            struct vm_area *right=create_vm_area_node(regend,vma->vm_end,vma->access_flags);
            vma->vm_end=regend;
            vma->vm_next=right;
        }
        vma->access_flags = prot;

        //Attempt to merge with the previous node (if contiguous and same protection).
        if (prev && prev->access_flags == prot && prev->vm_end == vma->vm_start) 
        {
            prev->vm_end = vma->vm_end;
            prev->vm_next = vma->vm_next;
            os_free(vma, sizeof(struct vm_area));
            stats->num_vm_area--;
            vma = prev;
        }
        
        //Merge with next
        if (vma->vm_next && vma->vm_next->access_flags == prot && vma->vm_end == vma->vm_next->vm_start) 
        {
            struct vm_area *temp = vma->vm_next;
            vma->vm_end = temp->vm_end;
            vma->vm_next = temp->vm_next;
            os_free(temp, sizeof(struct vm_area));
            stats->num_vm_area--;
        }
        vma = next_vma;
    }

    //Part 2 (page table)
    u64 *pgd_virtual = osmap(current->pgd);

    //Loop through each page in the virtual address range
    for (u64 a = regstart; a < regend; a += PAGE_SIZE) 
    {
        //Extract indices for each level of the page table hierarchy
        u64 pgd_idx = (a >> 39) & 0x1FF;   //Page Global Directory index
        u64 pud_idx = (a >> 30) & 0x1FF;   //Page Upper Directory index
        u64 pmd_idx = (a >> 21) & 0x1FF;   //Page Middle Directory index
        u64 pte_idx = (a >> 12) & 0x1FF;   //Page Table Entry index

        u64 *pgd_loc = pgd_virtual + pgd_idx;
        if (!(*pgd_loc & 1)) continue; //If not present, skip
        //If present, and write protection requested, set writable bit (bit 3)
        if ((*pgd_loc) & 1)
        {
            //present bit is 1
            if ((prot & PROT_WRITE) != 0)
            {
                *(pgd_loc) = (*pgd_loc) | 8;
            }
        }

        u64 *pud_virtual = (u64*)osmap((*pgd_loc) >> 12);
        u64 *pud_loc     = pud_virtual + pud_idx;
        if (!(*pud_loc & 1)) continue;
        if ((*pud_loc) & 1)
        {
            //present bit is 1
            if ((prot & PROT_WRITE) != 0)
            {
                *(pud_loc) = (*pud_loc) | 8;
            }
        }
    
        u64 *pmd_virtual = (u64*)osmap((*pud_loc) >> 12);
        u64 *pmd_loc     = pmd_virtual + pmd_idx;
        if (!(*pmd_loc & 1)) continue;
        if ((*pmd_loc) & 1)
        {
            //present bit is 1
            if ((prot & PROT_WRITE) != 0)
            {
                *(pmd_loc) = (*pmd_loc) | 8;
            }
        }
    
        u64 *pte_virtual = (u64*)osmap((*pmd_loc) >> 12);
        u64 *pte_loc     = pte_virtual + pte_idx;
        if ((*pte_loc) & 1)
        {
            //present bit is 1
            if ((prot & PROT_WRITE) != 0)
            {
                //If ref count is 1, it's safe to mark as writable
                u64 shared_pfn = (*pte_loc);
                u32 shared_pfn_physical = (shared_pfn >> 12);
                if (get_pfn_refcount(shared_pfn_physical) == 1)
                {
                    *(pte_loc) = (*pte_loc) | 8;
                }
            }
            else
            {
                //If write protection is not needed, clear the writable bit
                u64 clearwrite = 1;
                u64 mask = ~(clearwrite << 3);
                *(pte_loc) = (*pte_loc) & mask;
            }
        }
        else
        {
            continue; //present bit not found so nothing done
        }
        //Ensure TLB is updated for this page
        flush_tlbs_page(a);
    }

    return 0;
}

/**
 * mmap system call implementation.
 */
// Round up to the next multiple of PAGE_SIZE
// Helper functions for alignment
ul align_down(ul addr)
{
    return addr - (addr % PAGE_SIZE);
}

ul align_up(ul addr)
{
    if (addr % PAGE_SIZE == 0)
        return addr;
    return addr + (PAGE_SIZE - addr % PAGE_SIZE);
}

// function to count the number of vm areas in the linked list
int count_vm_area(struct vm_area *head)
{
    int count = 0;
    for (struct vm_area *temp = head; temp != NULL; temp = temp->vm_next)
        count++;
    return count;
}

// mmap internal implementation
long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{
    ul start_addr_hint, alloc_addr_start, alloc_addr_end;
    int is_allocated = 0;

    if (length <= 0) // checking if length given is vald or not
    {
        return -EINVAL;
    }

    // aligning the length in multiple of page size
    length = align_up(length);

    // case when user provided MAP_FIXED flag
    if (flags & MAP_FIXED)
    {
        start_addr_hint = align_down(addr); // we are aligning down the address so that we a start addr hint
        alloc_addr_end = start_addr_hint + length;

        // if that area is out of bounds
        if (start_addr_hint < MMAP_AREA_START || alloc_addr_end > MMAP_AREA_END)
        {
            return -EINVAL;
        }
    }
    else
    {
        // if user gave that addr as a hint
        if (addr != 0)
        {
            start_addr_hint = align_down(addr); // we are aligning down the address so that we a start addr hint
        }
        else
        {
            start_addr_hint = MMAP_AREA_START; // else if no addr is given we will start searching from MMAP_AREA_START
        }
    }

    // if linked list doesn't have dummy node we need to isert it
    if (current->vm_area == NULL)
    {
        current->vm_area = create_vm_area_node(MMAP_AREA_START, MMAP_AREA_START + PAGE_SIZE, 0);
        if (current->vm_area == NULL)
        {
            return -ENOMEM; // the node is not allocated due to insufficient menory
        }
    }

    // checking the constraints that vm_area should have 128 nodes
    if (count_vm_area(current->vm_area) >= 128)
    {
        return -EINVAL;
    }

    // we start search for node too allocate
    if (flags & MAP_FIXED)
    {
        // checking if it can be allocated or not
        for (struct vm_area *cur = current->vm_area; cur != NULL; cur = cur->vm_next)
        {
            if (!(alloc_addr_end <= cur->vm_start || start_addr_hint >= cur->vm_end))
            {
                return -EINVAL; // there is overlap between addresses
            }
        }
        alloc_addr_start = start_addr_hint; // setted the start address from where we need to add the node
    }
    else // case when the parameter is not MAP_FIXED
    {

        ul candidate_start_addr = start_addr_hint;

        struct vm_area *prev = NULL, *cur = current->vm_area;

        // traversing the linked list to find a suitable position
        while (cur != NULL)
        {
            if (candidate_start_addr + length <= cur->vm_start) // valid position found
            {
                break;
            }
            candidate_start_addr = cur->vm_end;
            prev = cur;
            cur = cur->vm_next;
        }

        if (candidate_start_addr + length > MMAP_AREA_END) // if lenth is not suitabke we can't allocate
        {
            return -EINVAL;
        }
        alloc_addr_start = candidate_start_addr;
        alloc_addr_end = alloc_addr_start + length;
    }

    // creating new node to be aded
    struct vm_area *new_node = create_vm_area_node(alloc_addr_start, alloc_addr_start + length, prot);
    if (new_node == NULL) // we are out of memory
    {
        return -ENOMEM;
    }

    // finding the positon where we need to add the node
    struct vm_area *prev = NULL, *curr = current->vm_area;
    while (curr && curr->vm_start < alloc_addr_start)
    {
        prev = curr;
        curr = curr->vm_next;
    }
    new_node->vm_next = curr;
    if (prev != NULL)
    {
        prev->vm_next = new_node;
    }
    else
    {
        current->vm_area = new_node;
    }

    // left merging if possible
    if (prev != NULL && prev->access_flags == prot && prev->vm_end == new_node->vm_start)
    {
        prev->vm_end = new_node->vm_end;
        prev->vm_next = new_node->vm_next;
        os_free(new_node, sizeof(struct vm_area)); // freeing the node
        stats->num_vm_area--;
        new_node = prev;
    }

    // right merging if possible
    if (new_node->vm_next != NULL && new_node->vm_next->access_flags == prot && new_node->vm_next->vm_start == new_node->vm_end)
    {
        struct vm_area *temp = new_node->vm_next;
        new_node->vm_end = temp->vm_end;
        new_node->vm_next = temp->vm_next;
        os_free(temp, sizeof(struct vm_area)); // freeing the node
        stats->num_vm_area--;
    }

    return alloc_addr_start; // return the start address
}


/**
 * munmap system call implemenations
 */
long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    //Length must be positive and address must be page-aligned
    if(length<=0 || addr%PAGE_SIZE!=0)
    {
        return -EINVAL;
    }
    //u64 len_to_be_removed = page_aligned_len(length);
    u64 unmap_start = addr;
    u64 npages = (length + PAGE_SIZE - 1) / PAGE_SIZE;
    u64 unmap_end = addr + npages * PAGE_SIZE;
    
    struct vm_area *vma = current->vm_area;
    struct vm_area *prev=NULL;
    int unmapped = 0;

    //Traverse the vm_area list to find the regions
    while(vma)
    {
        struct vm_area *next=vma->vm_next;
        //Skip non-overlapping regions
        if(unmap_end<=vma->vm_start || unmap_start>=vma->vm_end)
        {
            prev=vma;
            vma=next;
            continue;
        }

        //Case 1: The entire vma lies within the unmap range — delete it
        if(unmap_start<=vma->vm_start && unmap_end>=vma->vm_end)
        {
            if(prev) prev->vm_next=next;
            else current->vm_area=next;
            os_free(vma,sizeof(struct vm_area));
            stats->num_vm_area--;
            vma=next;
            unmapped=1;
            continue;
        }

        //Case 2: The unmap range chops off the beginning of the vma
        if(unmap_start<=vma->vm_start && unmap_end<vma->vm_end)
        {
            vma->vm_start=unmap_end;
            unmapped=1;
            continue;
        }

        //Case 3: The unmap range chops off the end of the vma
        if(unmap_start>vma->vm_start && unmap_end>=vma->vm_end)
        {
            vma->vm_end=unmap_start;
            unmapped=1;
            vma=next;
            continue;
        }

        //Case 4: The unmap range splits the vma into two parts
        if(unmap_start>vma->vm_start && unmap_end<vma->vm_end)
        {
            struct vm_area *right=create_vm_area_node(unmap_end, vma->vm_end, vma->access_flags);
            if(!right) return -EINVAL;

            right->vm_next=vma->vm_next;
            vma->vm_next=right;
            vma->vm_end=unmap_start;
            unmapped=1;
            break;
        }
        vma=next;

    }

    //Walk through the page tables and unmap the actual physical pages
    for (u64 a = unmap_start; a < unmap_end; a += PAGE_SIZE) 
    {
        u64 *pgd = (u64 *)osmap(current->pgd);
        u64 pgd_idx = (a >> 39) & 0x1FF;
        u64 pud_idx = (a >> 30) & 0x1FF;
        u64 pmd_idx = (a >> 21) & 0x1FF;
        u64 pte_idx = (a >> 12) & 0x1FF;
        
        //Walk through page table levels: PGD -> PUD -> PMD -> PTE
        u64 *pgd_loc = pgd + pgd_idx;
        if (!(*pgd_loc & 1)) continue;
    
        u64 *pud = (u64 *)osmap((*pgd_loc) >> 12);
        u64 *pud_loc = pud + pud_idx;
        if (!(*pud_loc & 1)) continue;
    
        u64 *pmd = (u64 *)osmap((*pud_loc) >> 12);
        u64 *pmd_loc = pmd + pmd_idx;
        if (!(*pmd_loc & 1)) continue;
    
        u64 *pte = (u64 *)osmap((*pmd_loc) >> 12);
        u64 *pte_loc = pte + pte_idx;
        if (!(*pte_loc & 1)) continue;
    
        //PFN is the top bits of the PTE
        //Extract the PFN (Page Frame Number) from the PTE by shifting out the lower 12 bits (flags)
        u64 pfn_to_free = (*pte_loc) >> 12;

        //Decrement the reference count for this PFN
        put_pfn(pfn_to_free);

        //If no other mapping is using this PFN (refcount is zero), free the physical page
        if (get_pfn_refcount(pfn_to_free) == 0)
        {
            os_pfn_free(USER_REG, pfn_to_free);  //Release the physical frame back to the user pool
        }

        //Clear the PTE entry
        *(pte_loc) = 0x0;

        //Flush the TLB for this virtual page
        flush_tlbs_page(a);
    }

    return unmapped ? 0 : -EINVAL;
}



/**
* Function will invoked whenever there is page fault for an address in the vm area region
* created using mmap
*/

long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    struct vm_area *head = current->vm_area->vm_next;

    // findin the vm area node corresponding to the given address
    while (head != NULL)
    {
        if (addr >= head->vm_start && addr < head->vm_end)
        {
            break;
        }
        head = head->vm_next;
    }

    if (head == NULL) // no valid vm_area node found
    {
        return -1;
    }

    if (head->access_flags == PROT_READ)
    {
        if (error_code == 0x6) // attempted write on a read only page
        {
            return -1;
        }
    }
    // printk("inside pagefault code\n");
    if (error_code == 0x7) // case of cow falut
    {
        return handle_cow_fault(current, addr, head->access_flags);
    }

    u64 *virtual_pgd = (u64 *)osmap(current->pgd); // virtual location pointer to pgd table

    u64 n = addr;

    u64 pfn_va = n & MASK_12;
    n >>= 12;

    u64 pte_va = n & MASK_9; // pte offset
    n >>= 9;

    u64 pmd_va = n & MASK_9; // pmd offset
    n >>= 9;

    u64 pud_va = n & MASK_9; // pud offset
    n >>= 9;

    u64 pgd_va = n & MASK_9; // pgd offset
    n >>= 9;

    // now adding the offset
    u64 *location_pgd = virtual_pgd + pgd_va; // computing the entry of pgd

    if ((*location_pgd) & 1) // checking if entry is valid or not
    {
        if ((head->access_flags & PROT_WRITE) != 0)
        {
            *location_pgd = (*location_pgd) | 8; // setting the read/write bit
        }
    }
    else // we have to allocate a page for it
    {
        u64 allocate_pud = (u64)osmap(os_pfn_alloc(OS_PT_REG));
        *location_pgd = ((allocate_pud >> 12) << 12) | ((head->access_flags & PROT_WRITE) ? 9 : 1); // here 9 means the entry is valid along with read/write bit is set 1 corresonds to only present bit is set
        *location_pgd = (*location_pgd) | 16;
    }

    u64 *location_pud = (u64 *)osmap((*location_pgd) >> 12) + pud_va; // we right shifted the address by 12 bits as we know that from 12th bit onwards we will get pfn of the next level
    if ((*location_pud) & 1)                                          // checking if entry is valid or not
    {
        if ((head->access_flags & PROT_WRITE) != 0)
        {
            *location_pud = (*location_pud) | 8; // setting the read/write bit
        }
    }
    else // we have to allocate a page for it
    {
        u64 allocate_pmd = (u64)osmap(os_pfn_alloc(OS_PT_REG));
        *location_pud = ((allocate_pmd >> 12) << 12) | ((head->access_flags & PROT_WRITE) ? 9 : 1); // here 9 means the entry is valid along with read/write bit is set 1 corresonds to only present bit is set
        *location_pud = (*location_pud) | 16;
    }

    u64 *location_pmd = (u64 *)osmap((*location_pud >> 12)) + pmd_va; // we right shifted the address by 12 bits as we know that from 12th bit onwards we will get pfn of the next level
    if ((*location_pmd) & 1)                                          // checking if entry is valid or not
    {
        if ((head->access_flags & PROT_WRITE) != 0)
        {
            *location_pmd = (*location_pmd) | 8; // setting the read/write bit
        }
    }
    else // we have to allocate a page for it
    {
        u64 allocate_pte = (u64)osmap(os_pfn_alloc(OS_PT_REG));
        *location_pmd = ((allocate_pte >> 12) << 12) | ((head->access_flags & PROT_WRITE) ? 9 : 1); // here 9 means the entry is valid along with read/write bit is set 1 corresonds to only present bit is set
        *location_pmd = (*location_pmd) | 16;
    }
    // getting entry of pgd of parent
    u64 *location_pte = (u64 *)osmap((*location_pmd) >> 12) + pte_va; // we right shifted the address by 12 bits as we know that from 12th bit onwards we will get pfn of the next level
    if ((*location_pte) & 1)                                          // checking if entry is valid or not
    {
        if ((head->access_flags & PROT_WRITE) != 0)
        {
            *location_pte = (*location_pte) | 8; // setting the read/write bit
        }
    }
    else // we have to allocate a page for it
    {
        u64 allocate_pfn = (u64)osmap(os_pfn_alloc(USER_REG));
        *location_pte = ((allocate_pfn >> 12) << 12) | ((head->access_flags & PROT_WRITE) ? 9 : 1); // here 9 means the entry is valid along with read/write bit is set 1 corresonds to only present bit is set
        *location_pte = (*location_pte) | 16;
    }
    return 1;
}

void create_new_pgtlb(struct exec_context *parent, struct exec_context *child, u64 virtual_addr, int permissions)
{
    u64 n = virtual_addr;

    u64 pfn_va = n & MASK_12;
    n >>= 12;

    u64 pte_va = n & MASK_9; // pte offset
    n >>= 9;

    u64 pmd_va = n & MASK_9; // pmd offset
    n >>= 9;

    u64 pud_va = n & MASK_9; // pud offset
    n >>= 9;

    u64 pgd_va = n & MASK_9; // pgd offset
    n >>= 9;

    u64 *pgd_virtuel_child = (u64 *)osmap(child->pgd);   // virtual location pointer to pgd table of parent
    u64 *pgd_virtuel_parent = (u64 *)osmap(parent->pgd); // virtual location pointer to pgd table of child

    u64 *pgd_parent_location = pgd_virtuel_parent + pgd_va; // getting entry of pgd of parent
    u64 *pgd_child_location = pgd_virtuel_child + pgd_va;   // getting entry of pgd of child

    // replication the pgd table entries for the child entries
    if ((*pgd_child_location) & 1)
    {
        if ((permissions & PROT_WRITE) != 0)
        {
            *(pgd_child_location) = (*pgd_child_location) | 8; // we setted the write bit
        }
    }
    else
    {
        if ((*pgd_parent_location) & 1)
        {
            u64 allocate_pud = (u64)osmap(os_pfn_alloc(OS_PT_REG));
            *(pgd_child_location) = ((allocate_pud >> 12) << 12) | ((permissions & PROT_WRITE) ? 9 : 1);
            *(pgd_child_location) = (*pgd_child_location) | 16; // to make it os managed entry
        }
        else
        {
            return;
        }
    }

    u64 *pud_parent_location = (u64 *)osmap(((*pgd_parent_location >> 12))) + pud_va;
    u64 *pud_child_location = (u64 *)osmap(((*pgd_child_location >> 12))) + pud_va;

    // replication the pud table entries for the child entries
    if ((*pud_child_location) & 1) // if child pud entry has vaild bit
    {
        if ((permissions & PROT_WRITE) != 0)
        {
            *(pud_child_location) = (*pud_child_location) | 8; // we setted the write bit
        }
    }
    else
    {
        if ((*pud_parent_location) & 1)
        {
            u64 allocate_pmd = (u64)osmap(os_pfn_alloc(OS_PT_REG));
            *(pud_child_location) = ((allocate_pmd >> 12) << 12) | ((permissions & PROT_WRITE) ? 9 : 1);
            *(pud_child_location) = (*pud_child_location) | 16; // to make it os managed entry
        }
        else
        {
            return;
        }
    }

    u64 *pmd_parent_location = (u64 *)osmap(((*pud_parent_location >> 12))) + pmd_va;
    u64 *pmd_child_location = (u64 *)osmap(((*pud_child_location >> 12))) + pmd_va;

    // replication the pmd table entries for the child entries
    if ((*pmd_child_location) & 1) // if child pmd entry has vaild bit
    {
        if ((permissions & PROT_WRITE) != 0)
        {
            *(pmd_child_location) = (*pmd_child_location) | 8; // we setted the write bit
        }
    }
    else
    {
        if ((*pmd_parent_location) & 1)
        {
            u64 allocate_pte = (u64)osmap(os_pfn_alloc(OS_PT_REG));
            *(pmd_child_location) = ((allocate_pte >> 12) << 12) | ((permissions & PROT_WRITE) ? 9 : 1);
            *(pmd_child_location) = (*pmd_child_location) | 16; // to make it os managed entry
        }
        else
        {
            return;
        }
    }

    u64 *pte_parent_location = (u64 *)osmap(((*pmd_parent_location >> 12))) + pte_va;
    u64 *pte_child_location = (u64 *)osmap(((*pmd_child_location >> 12))) + pte_va;

    // replication the pte table entries for the child entries
    if((*pte_parent_location) &1)
    {
        u64 parent_pte = *pte_parent_location;
        // Clear write bit for BOTH parent and child
        *pte_parent_location = parent_pte & ~(1ull << 3); // Parent becomes read-only
        u64 child_pte = parent_pte & ~(1ull << 3);         // Child inherits read-only
        *pte_child_location = child_pte;
        get_pfn(parent_pte >> 12); // Increment refcount
    }
    else
    {
        *(pte_child_location)=0x0;
    }
}

/**
* cfork system call implemenations
* The parent returns the pid of child process. The return path of
* the child process is handled separately through the calls at the
* end of this function (e.g., setup_child_context etc.)
*/

long do_cfork()
{
    u32 pid;
    struct exec_context *new_ctx = get_new_ctx();
    struct exec_context *ctx = get_current_ctx();
    /* Do not modify above lines
    *
    * */
    /*--------------------- Your code [start]---------------*/


    // copying contents form parent to child process
    pid = new_ctx->pid;
    new_ctx->ppid = ctx->pid;
    new_ctx->alarm_config_time = ctx->alarm_config_time;
    new_ctx->ticks_to_alarm = ctx->ticks_to_alarm;
    new_ctx->ticks_to_sleep = ctx->ticks_to_sleep;
    new_ctx->pending_signal_bitmap = ctx->pending_signal_bitmap;
    new_ctx->regs = ctx->regs;
    new_ctx->state = ctx->state;
    new_ctx->used_mem = ctx->used_mem;
    new_ctx->type = ctx->type;

    // copying vm ara begins
    struct vm_area *head = NULL, *curr = NULL, *prev_head = ctx->vm_area;

    while (prev_head != NULL)
    {
        struct vm_area *new_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
        new_node->access_flags = prev_head->access_flags;
        new_node->vm_start = prev_head->vm_start;
        new_node->vm_end = prev_head->vm_end;
        new_node->vm_next = NULL;

        if (head == NULL)//if current head node is null
        {
            head = new_node;
            curr = new_node;
        }
        else
        {
            curr->vm_next = new_node;
            curr = curr->vm_next;
        }
        prev_head = prev_head->vm_next;
    }
    new_ctx->vm_area = head;//settting the head of the child vm_area linked list

    // cpoying name so that child also inherit the same identity
    for (int i = 0; i < CNAME_MAX; i++)
    {
        new_ctx->name[i] = ctx->name[i];
    }

    // copying stack segments
    for (int i = 0; i < MAX_MM_SEGS; i++)
    {
        new_ctx->mms[i] = ctx->mms[i];
    }

    // copying file decripters
    for (int i = 0; i < MAX_OPEN_FILES; i++)
    {
        new_ctx->files[i] = ctx->files[i];
    }

    // copying signal handlers so that child behaves in the same way as parent does when it recieved some signal
    for (int i = 0; i < MAX_SIGNALS; i++)
    {
        new_ctx->sighandlers[i] = ctx->sighandlers[i];
    }

    // page allocation to hold child pgd(page global directory)
    new_ctx->pgd = os_pfn_alloc(OS_PT_REG);

    // vm_area page tables
    struct vm_area *temp = new_ctx->vm_area;
    u64 start = 0, end = 0;
    //building page table for all entries
    while (temp != NULL)
    {
        for (u64 start = temp->vm_start; start < temp->vm_end; start += PAGE_SIZE)
        {
            create_new_pgtlb(ctx, new_ctx, start, temp->access_flags);
        }
        temp = temp->vm_next;
    }

    //building page table for each memory segments
    for (int i = 0; i < MAX_MM_SEGS; i++)
    {
        if (i == MM_SEG_STACK)//for stack segment we will map until the fixed end
        {
            end = new_ctx->mms[i].end;
        }
        else //for all other segment we will map only the pages that are actually being used
        {
            end = new_ctx->mms[i].next_free;
        }
        for (u64 start = new_ctx->mms[i].start; start < end; start += PAGE_SIZE) //start building page table
        {
            create_new_pgtlb(ctx, new_ctx, start, new_ctx->mms[i].access_flags);
        }
    }

    // flush the tlb
    flush_tlbs();
    /*--------------------- Your code [end] ----------------*/

    /*
    * The remaining part must not be changed
    */
    copy_os_pts(ctx->pgd, new_ctx->pgd);
    do_file_fork(new_ctx);
    setup_child_context(new_ctx);
    return pid;
}



/* Cow fault handling, for the entire user address space
 * For address belonging to memory segments (i.e., stack, data) 
 * it is called when there is a CoW violation in these areas. 
 *
 * For vm areas, your fault handler 'vm_area_pagefault'
 * should invoke this function
 * */
//Function to handle cow fault
long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{
    if((access_flags&2)==0){
        return -1;
    }
    u64* virtual_pgd=(u64*)osmap(current->pgd); //virtual address of the PGD
 
    u64 n=vaddr;

    //Extract page table indices for each level using bit masks and shifts
    u64 pfn_va = n & MASK_12;  //Offset within page 
    n >>= 12;

    u64 pte_va = n & MASK_9;   //Page Table Entry index
    n >>= 9;

    u64 pmd_va = n & MASK_9;   //Page Middle Directory index
    n >>= 9;

    u64 pud_va = n & MASK_9;   //Page Upper Directory index
    n >>= 9;

    u64 pgd_va = n & MASK_9;   //Page Global Directory index
    n >>= 9;

    //now adding the offset
    u64 *location_pgd=virtual_pgd+pgd_va;
    
    if((*location_pgd)&1)//checking if entry is valid or not 
    {
        if((access_flags & PROT_WRITE)!=0){
            *location_pgd=(*location_pgd) | 8; //Set write bit

        }
    }
    else
    {
        //Allocate a new page table for PUD level
        u64 allocate_pud = (u64)osmap(os_pfn_alloc(OS_PT_REG));
        *location_pgd = ((allocate_pud >> 12) << 12) | ((access_flags & PROT_WRITE) ? 9 : 1); //Present + RW
        *location_pgd |= 16; //User-accessible bit
    }

    //PUD entry
    u64* location_pud=(u64*)osmap((*location_pgd)>>12)+pud_va;
    if((*location_pud)&1)//checking if entry is valid or not 
    {
        if((access_flags & PROT_WRITE)!=0){
            *location_pud=(*location_pud) | 8;

        }
    }
    else //we have to allocate a page for it
    {
        u64 allocate_pmd=(u64)osmap(os_pfn_alloc(OS_PT_REG));
        *location_pud=((allocate_pmd>>12)<<12) | ((access_flags & PROT_WRITE) ? 9 : 1);
        *location_pud=(*location_pud) | 16;
    }

    //PMD entry
    u64* location_pmd=(u64*)osmap((*location_pud>>12))+pmd_va;
    if((*location_pmd)&1)//checking if entry is valid or not 
    {
        if((access_flags & PROT_WRITE)!=0){
            *location_pmd=(*location_pmd) | 8;

        }
    }
    else //we have to allocate a page for it
    {
        u64 allocate_pte=(u64)osmap(os_pfn_alloc(OS_PT_REG));
        *location_pmd=((allocate_pte>>12)<<12) | ((access_flags & PROT_WRITE) ? 9 : 1);
        *location_pmd=(*location_pmd) | 16;
    }

    //PTE table
    u64* location_pte=(u64*)osmap((*location_pmd)>>12)+pte_va;
    if((*location_pte)&1)//checking if entry is valid or not 
    {
        u64 shared_pfn = (*location_pte);
        u32 shared_pfn_physical = (shared_pfn >> 12);

        //If PFN is shared by multiple processes
        if (get_pfn_refcount(shared_pfn_physical) >= 2)
        {
            put_pfn(shared_pfn_physical); //Reduce reference for the shared page

            //Allocate a private page for this process
            u64 pfn_allocated = (u64)osmap(os_pfn_alloc(USER_REG));
            *(location_pte) = ((pfn_allocated >> 12) << 12) | ((access_flags & PROT_WRITE) ? 9 : 1);
            *(location_pte) = (*location_pte) | 16;

            //Copy content from shared page to new page
            memcpy(osmap(((*location_pte) >> 12)), osmap(shared_pfn_physical), PAGE_SIZE);
        }
        else if (get_pfn_refcount(shared_pfn_physical) == 1)
        { 
            //Page is exclusively owned — just set write permission if needed
            if ((access_flags & PROT_WRITE) != 0)
            {
                *(location_pte) = (*location_pte) | 8;
            }
        }
    }
    else //we have to allocate a page for it
    {
        u64 allocate_pfn=(u64)osmap(os_pfn_alloc(USER_REG));
        *location_pte=((allocate_pfn>>12)<<12) | ((access_flags & PROT_WRITE) ? 9 : 1);
        *location_pte=(*location_pte) | 16;
    }
    flush_tlbs();

    return 1;
}
