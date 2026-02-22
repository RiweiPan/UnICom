#ifndef LINUX_NAP_SCHED_H
#define LINUX_NAP_SCHED_H

#include <linux/sched.h>
#include "nap_nvme.h"

static void nap_submit_update_sched_state(struct task_struct *task, int mode, int state);
{
	struct rq_flags rf;
	struct rq *rq;
	struct sched_entity *se;

    rq = this_rq_lock_irq(&rf);

    se = &task->se;
    update_rq_clock(rq);
    update_curr(task_cfs_rq(task));
    rq_clock_skip_update(rq);

    if(likely(se->cskip >= 0)) {
        se->cskip += state;
    }
        
    preempt_disable();
    rq_unlock_irq(rq, &rf);
    sched_preempt_enable_no_resched();
}

static int nap_complete_sched_state(struct task_struct *task, int mode, int state)
{
	struct rq_flags rf;
	struct rq *rq;
    struct sched_entity *se;
	int nr_running = 0;

    rq_lock_irq(rq, &rf);
    se = &task->se;

    if(likely(se->cskip <= 0)) {
        se->cskip += state;
        if(likely(se->cskip == 0)) {
            struct cfs_rq *cfs_rq = task_cfs_rq(task);
            if(cfs_rq->curr) { 
                if(cfs_rq->curr != se && cfs_rq->curr->my_io_flag != 1) { // only preempt non-I/O thread
                    set_tsk_need_resched(task);
                    resched_curr(rq);
                }
            }
        }
    }

    preempt_disable();
    rq_unlock_irq(rq, &rf);
    sched_preempt_enable_no_resched();

    return 0;
}

#endif