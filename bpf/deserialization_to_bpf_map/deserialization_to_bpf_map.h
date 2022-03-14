#ifndef __DESERIALIZATION_TO_BPF_MAP_H__
#define __DESERIALIZATION_TO_BPF_MAP_H__

#define MAX_OUTTER_MAP_ENTRIES	(10000)

int deserial_update_elem(void *key, void *value);
void* deserial_lookup_elem(void *key, const void *msg_desciptor);
void deserial_free_elem(void *value);
int deserial_delete_elem(void *key, const void *msg_desciptor);


#endif /* __DESERIALIZATION_TO_BPF_MAP_H__ */
