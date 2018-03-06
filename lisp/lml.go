//
// lml.go
//
// This file contains functions for the "Longest Match Lookup (LML)" support.
// It is used by xtr.go for doing map-cache lookups for forwarding. And is
// used by ipc.go to add and delete map-cache entries when the lispers.net
// control-plane tells it so.
//
package main

import "fmt"
import "net"

//
// If this is changed, change lml_clear_hash_table() too.
//
var lisp_lml_cache [129]*Lisp_hash_table

type Lisp_hash_table struct {
	next_ht    int
	ht_count   int
	hash_table [256]*Lisp_map_cache   // 8-bit hash
}

//
// lisp_lml_add_entry
//
// Add an entry to the LML data structure.
//
func lisp_lml_add_entry(mc *Lisp_map_cache) {

	//
	// The EID-prefix slot in the array of hash-tables is based on its
	// prefix mask-length. Allocate memory for hash-table if this is the
	// first entry for the mask-length.
	//
	ht := lisp_lml_cache[mc.eid_prefix.mask_len]
	if (ht == nil) {
		ht = new(Lisp_hash_table)
		lisp_lml_cache[mc.eid_prefix.mask_len] = ht
	}

	//
	// Hash the address to get a hash-table slot between the values of 0 and
	// 255. Insert at slot by "pushing down" all othe entries.
	//
	hash := lisp_lml_hash(mc.eid_prefix.address, mc.eid_prefix.mask_len)
	mc.next_mc = ht.hash_table[hash]
	ht.hash_table[hash] = mc
	ht.ht_count += 1
}

//
// lisp_lml_delete_entry
//
// Remove entry from LML cache.
//
func lisp_lml_delete_entry(mc *Lisp_map_cache) {

	//
	// The EID-prefix slot in the array of hash-tables is based on its
	// prefix mask-length. If the array slot has no hash-table allocated,
	// then the EID-prefix is not in the table.
	//
	ht := lisp_lml_cache[mc.eid_prefix.mask_len]
	if (ht == nil) { return }

	//
	// Hash the address to get a hash-table slot between the values of 0 and
	// 255. Search for map-cache entry pointer. Use pointer to pointer to
	// relink.
	//
	hash := lisp_lml_hash(mc.eid_prefix.address, mc.eid_prefix.mask_len)
	for mce := &ht.hash_table[hash]; *mce != nil; mce = &((*mce).next_mc) {
		if (*mce == mc) {
			*mce = mc.next_mc
			ht.ht_count -= 1
			return
		}
	}
}

//
// lisp_lml_lookup
//
// The longest match data structure is an array of hash tables. The first
// level array is indexed by mask-length. So lisp_lml_cache[129] is the first
// hash-table that is checked.
//
func lisp_lml_lookup(dest Lisp_address) *Lisp_map_cache {
	var start int
	
	if (dest.lisp_is_ipv4()) {
		start = 32
	} else if (dest.lisp_is_ipv6()) {
		start = 128
	} else {
		return(nil)
	}

	for i := start; i >= 0; i-- {
		ht := lisp_lml_cache[i]
		if (ht == nil || ht.ht_count == 0) { continue }

		hash := lisp_lml_hash(dest.address, i)
		for mce := ht.hash_table[hash]; mce != nil; mce = mce.next_mc {
			if (mce.eid_prefix.lisp_more_specific(dest)) { return(mce) }
		}
	}
	return(nil)
}

//
// lisp_lml_exact_lookup
//
// Call lisp_lml_lookup() and then compare the mask-lengths to determine if
// the match is an exact match.
//
func lisp_lml_exact_lookup(address Lisp_address) *Lisp_map_cache {
	mc := lisp_lml_lookup(address)
	if (mc == nil || mc.eid_prefix.mask_len != address.mask_len) {
		return(nil)
	}
	return(mc)
}

//
// lisp_lml_hash
//
// Givene an address, return a hash value that is in range of 0 to 255. Make
// sure to zero out hosts bits so a prefix populated in a hash table can
// match the same hash table location with a destination used to be looked up.
//
func lisp_lml_hash(address net.IP, mask_len int) uint {
	hash := uint(0)
	mask := net.CIDRMask(mask_len, len(address) * 8)

	for i := 0; i < len(address); i++ {
		if (mask[i] == 0) {	break }
		addr_byte := uint(address[i]) & uint(mask[i])
		hash = hash ^ addr_byte
	}
	return(hash)
}

//
// lisp_lml_show
//
// Show internal representation of the LML data structure.
//
func lisp_lml_show() {
	count := 0
	ht_count := 0

	for i := 0; i < len(lisp_lml_cache); i++ {
		ht := lisp_lml_cache[i]
		if (ht == nil || ht.ht_count == 0) { continue }

		fmt.Printf("Hash table /%d, count %d\n", i, ht.ht_count)
		slot_count := 0
		for hash, slot := range ht.hash_table {
			if (slot == nil) { continue }

			slot_count += 1
			fmt.Printf("  Hash 0x%x: ", hash)
			ht_count = 0
			for mc := slot; mc != nil; mc = mc.next_mc {
				fmt.Printf("%s ", mc.eid_prefix.lisp_print_address(true))
				count += 1
				ht_count += 1
			}
			fmt.Printf("\n")
		}
		if (slot_count != 0) {
			fmt.Printf("Average slot collision: %d\n", ht_count / slot_count)
		}
	}

	fmt.Printf("Found %d entries\n", count)
}

//
// lisp_lml_walk
//
// Walk each entry of the LML table and return a *Lisp_map_cache. Passing
// in nil, gets you the first entry. Passing non-nil gets you the entry
// after the pointer passed in. Return nil when end of table.
//
func lisp_lml_walk(mc *Lisp_map_cache) *Lisp_map_cache {
	found := (mc == nil)

	for i := 0; i < len(lisp_lml_cache); i++ {
		ht := lisp_lml_cache[i]
		if (ht == nil || ht.ht_count == 0) { continue }

		for _, slot := range ht.hash_table {
			for mce := slot; mce != nil; mce = mce.next_mc {
				if (found) { return(mce) }
				if (mce == mc) { found = true }
			}
		}
	}
	return(nil)
}

//
// lml_clear_hash_table
//
// Remove all entries from LML hash-table.
//
func lml_clear_hash_table() {
	var new_cache [129]*Lisp_hash_table

	lisp_lml_cache = new_cache
}
