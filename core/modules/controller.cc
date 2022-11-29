#include "controller.h"

bool Controller::sortByVal(DyssectState* a, DyssectState* b) 
{
        return (a->prob2 > b->prob2);
}

ShardInfo *Controller::shards = 0;
uint32_t Controller::total_shards = 0;
rte_atomic32_t *Controller::epoch = 0;
