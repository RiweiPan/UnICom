#include "ext4.h"
#include "ext4_extents.h"

static int ext4_build_nap_mapping_table(struct nm_tree *nt, struct inode *inode, u64 start, u64 len)
{
    struct ext4_ext_path *path;
    struct ext4_extent_header *eh;
    struct ext4_extent *ex;
    int i, depth;
    unsigned int block = 0;

    if(!inode) return -EINVAL;

    /**
      * Note: this function is just for demo.
      * We only obtain the first extent node of this file because it is sufficient for our mapping purpose (support maximum 341 extents).
      * For production environment, this function should traverse all extents and build the mapping table accordingly.
      */
    path = ext4_find_extent(inode, block, NULL, 0);
    if (IS_ERR(path))
		return PTR_ERR(path);

    depth = ext_depth(inode);
    eh = path[depth].p_hdr;
    ex = EXT_FIRST_EXTENT(eh);

    // if (unlikely(depth > 0) || unlikely(le16_to_cpu(eh->eh_entries) == le16_to_cpu(eh->eh_max))) {
    //     printk(KERN_INFO "[Nap-Warn]: Extent tree has %d levels\n", depth + 1);
    // }

    for (i = 0; i < le16_to_cpu(eh->eh_entries); i++, ex++) {
        u64 blk_len = ext4_ext_get_actual_len(ex);
        u64 lba_start = le32_to_cpu(ex->ee_block);
        u64 pba_start = ext4_ext_pblock(ex);
        // printk(KERN_INFO "ext4: Extent %d: lba_start=%llu, blk_len=%llu, pba_start=%llu\n", i, lba_start, blk_len, pba_start);
		update_nm_tree(nt, lba_start, blk_len, pba_start);
	}

    if (path) {
        ext4_free_ext_path(path);
    }

    // traverse_nm_tree(nt);
    return 0;
}

struct nm_operations ext4_nm_ops = {
    .build_nap_mapping_table = ext4_build_nap_mapping_table,
};

void ext4_init_nm_ops(struct ext4_sb_info *sbi)
{
    sbi->nmap = kmalloc(sizeof(struct nap_mapping), GFP_KERNEL); // static struct nap_mapping ext4_nap_map;
    init_nap_mapping(sbi->nmap, &ext4_nm_ops);
}

void ext4_destroy_nm_ops(struct ext4_sb_info *sbi)
{
    destroy_nap_mapping(sbi->nmap);
    kfree(sbi->nmap);
    sbi->nmap = NULL;
}

