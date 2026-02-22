#include <linux/printk.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>
#include <linux/nap-map.h>

static inline struct nm_node *__attach_extent_node(struct nm_tree *et, struct nm_extent *ei,
				struct rb_node *parent, struct rb_node **p)
{
	struct nm_node *en;

	en = kmem_cache_alloc(et->nmap->nm_node_slab, GFP_ATOMIC);
	if (unlikely(!en))
		return NULL;

	
	en->extent = *ei;
	rb_link_node(&en->rb_node, parent, p);
	rb_insert_color(&en->rb_node, &et->root);
	return en;
}

static inline void __detach_extent_node(struct nm_tree *et, struct nm_node *en)
{
	rb_erase(&en->rb_node, &et->root);
	if (et->cached_en == en)
		et->cached_en = NULL;
	kmem_cache_free(et->nmap->nm_node_slab, en);
}

static void __release_extent_node(struct nm_tree *et, struct nm_node *en)
{
	__detach_extent_node(et, en);
}

static inline bool __is_extent_mergeable(struct nm_extent *back,
						struct nm_extent *front)
{
	return (back->lba_start + back->len == front->lba_start &&
			back->pba_start + back->len == front->pba_start);
}

static inline bool __is_back_mergeable(struct nm_extent *cur,
						struct nm_extent *back)
{
	return __is_extent_mergeable(back, cur);
}

static inline bool __is_front_mergeable(struct nm_extent *cur,
						struct nm_extent *front)
{
	return __is_extent_mergeable(cur, front);
}

static struct nm_node *__try_merge_extent_node(struct nm_tree *et, struct nm_extent *ei,
				struct nm_node *prev_ex,
				struct nm_node *next_ex)
{
	struct nm_node *en = NULL;

	if (prev_ex && __is_back_mergeable(ei, &prev_ex->extent)) {
		prev_ex->extent.len += ei->len;
		ei = &prev_ex->extent;
		en = prev_ex;
	}

	if (next_ex && __is_front_mergeable(ei, &next_ex->extent)) {
		if (en)
			__release_extent_node(et, prev_ex);
		next_ex->extent.lba_start = ei->lba_start;
		next_ex->extent.pba_start = ei->pba_start;
		next_ex->extent.len += ei->len;
		en = next_ex;
	}

	if (unlikely(!en))
		et->cached_en = en;

	return en;
}

static struct nm_node *__insert_extent_tree(struct nm_tree *et, struct nm_extent *ei,
				struct rb_node **insert_p,
				struct rb_node *insert_parent)
{
	struct rb_node **p = &et->root.rb_node;
	struct rb_node *parent = NULL;
	struct nm_node *en = NULL;

	if (insert_p && insert_parent) {
		parent = insert_parent;
		p = insert_p;
		goto do_insert;
	}

	while (*p) {
		parent = *p;
		en = rb_entry(parent, struct nm_node, rb_node);

		if (ei->lba_start < en->extent.lba_start)
			p = &(*p)->rb_left;
		else if (ei->lba_start >= en->extent.lba_start + en->extent.len)
			p = &(*p)->rb_right;
		else
			BUG();
	}
do_insert:
	en = __attach_extent_node(et, ei, parent, p);
	if (unlikely(!en))
		return NULL;
	et->cached_en = en;
	return en;
}

static struct nm_node *__lookup_extent_tree_ret(struct nm_tree *et,
				u64 lba,
				struct nm_node **prev_ex,
				struct nm_node **next_ex,
				struct rb_node ***insert_p,
				struct rb_node **insert_parent)
{
	struct rb_node **pnode = &et->root.rb_node;
	struct rb_node *parent = NULL, *tmp_node;
	struct nm_node *en = et->cached_en;

	*insert_p = NULL;
	*insert_parent = NULL;
	*prev_ex = NULL;
	*next_ex = NULL;

	if (RB_EMPTY_ROOT(&et->root))
		return NULL;

	if (en) {
		struct nm_extent *cei = &en->extent;

		if (cei->lba_start <= lba && cei->lba_start + cei->len > lba)
			goto lookup_neighbors;
	}

	while (*pnode) {
		parent = *pnode;
		en = rb_entry(*pnode, struct nm_node, rb_node);

		if (lba < en->extent.lba_start)
			pnode = &(*pnode)->rb_left;
		else if (lba >= en->extent.lba_start + en->extent.len)
			pnode = &(*pnode)->rb_right;
		else
			goto lookup_neighbors;
	}

	*insert_p = pnode;
	*insert_parent = parent;

	en = rb_entry(parent, struct nm_node, rb_node);
	tmp_node = parent;
	if (parent && lba > en->extent.lba_start)
		tmp_node = rb_next(parent);
	*next_ex = tmp_node ?
		rb_entry(tmp_node, struct nm_node, rb_node) : NULL;

	tmp_node = parent;
	if (parent && lba < en->extent.lba_start)
		tmp_node = rb_prev(parent);
	*prev_ex = tmp_node ?
		rb_entry(tmp_node, struct nm_node, rb_node) : NULL;
	return NULL;

lookup_neighbors:
	if (lba == en->extent.lba_start) {
		/* lookup prev node for merging backward later */
		tmp_node = rb_prev(&en->rb_node);
		*prev_ex = tmp_node ?
			rb_entry(tmp_node, struct nm_node, rb_node) : NULL;
	}
	if (lba == en->extent.lba_start + en->extent.len - 1) {
		/* lookup next node for merging frontward later */
		tmp_node = rb_next(&en->rb_node);
		*next_ex = tmp_node ?
			rb_entry(tmp_node, struct nm_node, rb_node) : NULL;
	}
	return en;
}


// pgoff_t fofs, block_t blkaddr, unsigned int len
static unsigned int update_extent_tree_range(struct nm_tree *et, u64 lba, u64 pba, u64 len)
{
	struct nm_node *en = NULL, *en1 = NULL;
	struct nm_node *prev_en = NULL, *next_en = NULL;
	struct nm_extent ei, dei;
	struct rb_node **insert_p = NULL, *insert_parent = NULL;
	u64 end = lba + len;
	u64 pos = lba;

	if (unlikely(!et || len == 0))
		return false;

	write_lock(&et->lock);
	dei.len = 0;

	/* 1. lookup first extent node in range [fofs, fofs + len - 1] */
	en = __lookup_extent_tree_ret(et, lba, &prev_en, &next_en,
					&insert_p, &insert_parent);
	if (!en)
		en = next_en;

	/* 2. invlidate all extent nodes in range [fofs, fofs + len - 1] */
	while (en && en->extent.lba_start < end) {
		u64 org_end;
		int parts = 0;	/* # of parts current extent split into */

		next_en = en1 = NULL;

		dei = en->extent;
		org_end = dei.lba_start + dei.len;

		if (pos > dei.lba_start) {
			en->extent.len = pos - en->extent.lba_start;
			prev_en = en;
			parts = 1;
		}

		if (end < org_end) {
			if (parts) {
				// set_extent_info(&ei, end,
				// 		end - dei.lba_start + dei.pba_start,
				// 		org_end - end);
				ei.lba_start = end;
				ei.pba_start = end - dei.lba_start + dei.pba_start;
				ei.len = org_end - end;
				en1 = __insert_extent_tree(et, &ei, NULL, NULL);
				next_en = en1;
			} else {
				en->extent.lba_start = end;
				en->extent.pba_start += end - dei.lba_start;
				en->extent.len -= end - dei.lba_start;
				next_en = en;
			}
			parts++;
		}

		if (!next_en) {
			struct rb_node *node = rb_next(&en->rb_node);

			next_en = node ?
				rb_entry(node, struct nm_node, rb_node)
				: NULL;
		}

		if (!parts)
			__release_extent_node(et, en);

		/*
		 * if original extent is split into zero or two parts, extent
		 * tree has been altered by deletion or insertion, therefore
		 * invalidate pointers regard to tree.
		 */
		if (parts != 1) {
			insert_p = NULL;
			insert_parent = NULL;
		}
		en = next_en;
	}

	/* 3. update extent in extent cache */
	if (pba) {
		// set_extent_info(&ei, lba, pba, len);
		ei.lba_start = lba;
		ei.pba_start = pba;
		ei.len = len;
		if (!__try_merge_extent_node(et, &ei, prev_en, next_en))
			__insert_extent_tree(et, &ei,
						insert_p, insert_parent);
	}

	write_unlock(&et->lock);
	return 0;
}

void update_nm_tree(struct nm_tree *nt, u64 lba, u64 len, u64 pba)
{
	update_extent_tree_range(nt, lba, pba, len);
}
EXPORT_SYMBOL_GPL(update_nm_tree);

int lookup_extent(struct nm_tree *et, u64 lba, struct nm_extent *extent)
{
	int ret = false;
    struct rb_node *node = et->root.rb_node;
	struct nm_node *en = et->cached_en;

	read_lock(&et->lock);

	if(en) {
		if (en->extent.lba_start <= lba && en->extent.lba_start + en->extent.len > lba) {
			*extent = en->extent;
			ret = true;
			goto out;
		}
	}
    
    while (node) {
        en = rb_entry(node, struct nm_node, rb_node);
        if (lba < en->extent.lba_start) {
            node = node->rb_left;
        } else if (lba >= en->extent.lba_start + en->extent.len) {
            node = node->rb_right;
        } else {
			et->cached_en = en;
			*extent = en->extent;
			ret = true;
            goto out; // found in tree
        }
    }
out:
	read_unlock(&et->lock);
    return ret;
}
EXPORT_SYMBOL_GPL(lookup_extent);

struct nm_extent *find_extent(struct nm_tree *et, u64 lba)
{
    struct rb_node *node = et->root.rb_node;

    while (node) {
        struct nm_node *en = rb_entry(node, struct nm_node, rb_node);
        if (lba < en->extent.lba_start) {
            node = node->rb_left;
        } else if (lba >= en->extent.lba_start + en->extent.len) {
            node = node->rb_right;
        } else {
            return &en->extent; // 找到
        }
    }
    return NULL; // 未找到
}
EXPORT_SYMBOL_GPL(find_extent);

void free_nm_tree(struct nm_tree *nt)
{
    struct rb_node *node, *next;
    struct nm_node *n;

	if (!nt)
		return;

	write_lock(&nt->lock);
    node = rb_first(&nt->root);
    while (node) {
        next = rb_next(node);
        n = container_of(node, struct nm_node, rb_node);
        __detach_extent_node(nt, n);
        node = next;
    }
	write_unlock(&nt->lock);

	kmem_cache_free(nt->nmap->nm_tree_slab, nt);
}
EXPORT_SYMBOL_GPL(free_nm_tree);

struct nm_tree *alloc_nm_tree(struct nap_mapping *nmap, struct inode *inode)
{
    int ret;
    struct nm_tree *nt;

    nt = kmem_cache_zalloc(nmap->nm_tree_slab, GFP_NOFS);
    if (!nt)
        return NULL;

    nt->root = RB_ROOT;
	nt->nmap = nmap;
	nt->cached_en = NULL;
	rwlock_init(&nt->lock);

    if(nmap->nm_ops) {
		// load extents to the tree
        ret = nmap->nm_ops->build_nap_mapping_table(nt, inode, 0, i_size_read(inode));
        if(ret < 0) {
            free_nm_tree(nt);
            return NULL;
        }
    }

    return nt;
}
EXPORT_SYMBOL_GPL(alloc_nm_tree);

int init_nap_mapping(struct nap_mapping *nmap, struct nm_operations *nm_ops)
{
	nmap->nm_tree_slab = kmem_cache_create("nm_tree_slab",
			sizeof(struct nm_tree), 0, SLAB_RECLAIM_ACCOUNT, NULL);
	if (!nmap->nm_tree_slab)
		goto fail;

	nmap->nm_node_slab = kmem_cache_create("nm_node_slab",
			sizeof(struct nm_node), 0, SLAB_RECLAIM_ACCOUNT, NULL);
	if (!nmap->nm_node_slab) {
		goto free_nm_tree_slab;
	}

	if(nm_ops != NULL)
		nmap->nm_ops = nm_ops;

	return 0;
free_nm_tree_slab:
	kmem_cache_destroy(nmap->nm_tree_slab);
fail:
	return -ENOMEM;
}
EXPORT_SYMBOL_GPL(init_nap_mapping);

void destroy_nap_mapping(struct nap_mapping *nmap)
{
	kmem_cache_destroy(nmap->nm_node_slab);
	kmem_cache_destroy(nmap->nm_tree_slab);
}
EXPORT_SYMBOL_GPL(destroy_nap_mapping);
