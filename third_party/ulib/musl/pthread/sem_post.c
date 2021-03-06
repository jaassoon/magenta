#include "futex_impl.h"
#include "pthread_impl.h"
#include <semaphore.h>

int sem_post(sem_t* sem) {
    int val, waiters;
    do {
        val = sem->__val[0];
        waiters = sem->__val[1];
        if (val == SEM_VALUE_MAX) {
            errno = EOVERFLOW;
            return -1;
        }
    } while (a_cas(sem->__val, val, val + 1 + (val < 0)) != val);
    if (val < 0 || waiters)
        __wake(sem->__val, 1);
    return 0;
}
