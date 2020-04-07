/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef DPMSG_H
#define DPMSG_H

typedef struct dpmsg {
	zmq_msg_t topic_msg;
	zmq_msg_t seqno_msg;
	zmq_msg_t data_msg;
} dpmsg_t;

int dpmsg_recv(zsock_t *sock, dpmsg_t *dpmsg);
int dpmsg_convert_zmsg(zmsg_t *zmsg, dpmsg_t *dpmsg);
void dpmsg_destroy(dpmsg_t *dpmsg);
int process_dpmsg(enum cont_src_en cont_src, dpmsg_t *dpmsg);
int process_ready_msg(enum cont_src_en cont_src, dpmsg_t *dpmsg);
int process_snapshot_one(enum cont_src_en cont_src, dpmsg_t *dpmsg, int *eof);

#endif /* DPMSG_H */
