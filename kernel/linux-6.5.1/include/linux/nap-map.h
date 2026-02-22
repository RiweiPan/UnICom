#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/rbtree.h>

// #define NAP_MAP_DEBUG

#define NAP_MAP_MAX_EXTENT_LEN (0xffffffffff - 1)

#ifdef NAP_MAP_DEBUG
#define nm_debug_log(fmt, ...) \
	do{printk("[NapMap]:(%s):%d: " fmt, __func__, __LINE__, ##__VA_ARGS__);} while(0)
#else
#define nm_debug_log(fmt, ...) \
	do{} while(0)
#endif

struct nm_extent {
    u64 lba_start; // offset / PAGE_SIZE
    u64 pba_start;
    u64 len;
};

struct nm_node {
    struct rb_node rb_node;
    struct nm_extent extent;
};

struct nm_tree {
    struct rb_root root;
    rwlock_t lock;
    struct nap_mapping *nmap;
    struct nm_node *cached_en; // test its performance
};

struct nm_operations {
	int (*build_nap_mapping_table)(struct nm_tree *nt, struct inode *inode, u64 start, u64 len);
    int (*nap_mapping_lookup)(struct inode *inode, u64 lba_start, u64 len);
};

struct nap_mapping {
    struct kmem_cache *nm_tree_slab;
    struct kmem_cache *nm_node_slab;
    struct nm_operations *nm_ops;
};

static inline int nmap_lookup_block_address(struct inode *inode, u64 lba, u64 len, u64 *pba)
{
    if(unlikely(!inode->i_op)) {
        return -EINVAL;
    }

	return inode->i_op->nap_mapping_lookup(inode, lba, len, pba);
}

int init_nap_mapping(struct nap_mapping *nmap, struct nm_operations *nm_ops);
void destroy_nap_mapping(struct nap_mapping *nmap);
struct nm_tree *alloc_nm_tree(struct nap_mapping *nmap, struct inode *inode);
void free_nm_tree(struct nm_tree *nt);
int lookup_extent(struct nm_tree *et, u64 lba_start, struct nm_extent *extent);
struct nm_extent *find_extent(struct nm_tree *et, u64 offset);
void update_nm_tree(struct nm_tree *et, u64 lba_start, u64 len, u64 pba);
