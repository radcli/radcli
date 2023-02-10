/*
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 *
 * Copyright 1992 Livingston Enterprises, Inc.
 *
 * Copyright 1992,1993, 1994,1995 The Regents of the University of Michigan
 * and Merit Network, Inc. All Rights Reserved
 *
 * Copyright (C) 2022 Cadami GmbH, info@cadami.net
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 */

#include <includes.h>
#include <radcli/radcli.h>
#include <pathnames.h>
#include <poll.h>

#include "sendserver_util.h"
#include "util.h"
#include "rc-md5.h"
#include "rc-hmac.h"

#if defined(__linux__)
#include <linux/in6.h>
#endif

struct rc_async_handle_list_member {
	struct rc_async_handle_list_member *previous, *next;
	struct rc_async_handle *hdl;
};


struct rc_multihandle {
	struct rc_async_handle_list_member *previous, *next;
};


/** Prepares a new multihandle to enqueue async requests into.
 *
 * @return Pointer to an allocated rc_multihandle on success, NULL on error.
 */
struct rc_multihandle *
rc_multi_create_multihandle(void)
{
	return calloc(1, sizeof(struct rc_multihandle));
}


/** Deallocates a rc_multihandle and all rc_async_handle requests
 * enqueued into it.
 *
 * @param mhdl a multihandle containing N parallel requests.
 */
void
rc_multi_destroy_multihandle(struct rc_multihandle *mhdl)
{
	struct rc_async_handle_list_member *member;

	if (!mhdl)
		return;

	while (mhdl->next) {
		rc_async_destroy_handle(mhdl->next->hdl);
		member = mhdl->next;
		mhdl->next = member->next;
		free(member);
	}

	free(mhdl);
}


/** Adds an rc_async_handle to an rc_multihandle for async processing.
 *
 * @return OK_RC (0) if the add succeeded, a negative error code otherwise.
 */
int
rc_multi_add(struct rc_multihandle *mhdl, struct rc_async_handle *hdl)
{
	struct rc_async_handle_list_member *member;

	if (!mhdl || !hdl)
		return ERROR_RC;

	member = calloc(1, sizeof(struct rc_async_handle_list_member));
	if (!member)
		return ERROR_RC;

	member->hdl = hdl;

	if (!mhdl->next) {
		/* Insert into empty list */
		mhdl->next = member;
		mhdl->previous = member;
	} else {
		/* insert front */
		member->next = mhdl->next;
		mhdl->next->previous = member;
		mhdl->next = member;
	}

	return 0;
}


static void
unlink_handle_member(struct rc_multihandle *mhdl,
		struct rc_async_handle_list_member *member)
{
	struct rc_async_handle_list_member *previous = member->previous;
	struct rc_async_handle_list_member *next = member->next;

	if (previous && next) {
		previous->next = next;
		next->previous = previous;
	} else if (previous && !next) {
		previous->next = NULL;
		mhdl->previous = previous;
	} else if (!previous && next) {
		mhdl->next = next;
		next->previous = NULL;
	} else {
		mhdl->next = NULL;
		mhdl->previous = NULL;
	}

	free(member);
}

/** Removes an rc_async_handle to an rc_multihandle.
 *
 * @return OK_RC (0) if the removal succeeded, a negative error code otherwise.
 */
int rc_multi_remove(struct rc_multihandle *mhdl, struct rc_async_handle *hdl)
{
	struct rc_async_handle_list_member *member = NULL;

	if (!mhdl)
		return ERROR_RC;

	for (member = mhdl->next; member; member = member->next) {
		if (member->hdl == hdl)
			break;
	}

	if (!member)
		return ERROR_RC;

	unlink_handle_member(mhdl, member);

	return OK_RC;
}


/** Find a done rc_async_handle in the rc_multihandle mhdl and remove it
 * from mhdl.  Return NULL if mhdl has no done handle.
 *
 * @note In order to remove all done handles, call this function repeatedly
 * until it return NULL.
 *
 * @param mhdl the rc_multihandle.
 * @return the extracted rc_async_handle or NULL.
 */
struct rc_async_handle *
rc_multi_remove_next_done(struct rc_multihandle *mhdl)
{
	struct rc_async_handle_list_member *iter;
	struct rc_async_handle *hdl;

	if (!mhdl)
		return NULL;

	for (iter = mhdl->next; iter; iter = iter->next)
		if (rc_async_is_done(iter->hdl))
			break;

	if (!iter)
		return NULL;

	hdl = iter->hdl;

	unlink_handle_member(mhdl, iter);

	return hdl;
}


/** Mark file descriptors for read in rfd and write in wfd according to the
 * state of the rc_multihandle mdhl. Also sets the poll-flags.
 *
 * @param mhdl a multihandle containing N parallel requests
 * @param rfd fd_set to mark file descriptors for read events
 * @param wfd fd_set to mark file descriptors for write events
 * @return the number of marked entries.
 */
int rc_multi_get_fd_set(struct rc_multihandle *mhdl,
		fd_set *rfd, fd_set *wfd)
{
	int fd;
	int i = 0;
	short events;
	struct rc_async_handle_list_member *iter;

	if (!mhdl)
		return 0;

	for (iter = mhdl->next; iter; iter = iter->next) {
		fd = rc_async_get_fd(iter->hdl);
		events = rc_async_get_events(iter->hdl);

		if (rfd && (events & POLLIN)) {
			FD_SET(fd, rfd);
			i++;
		}

		if (wfd && (events & POLLOUT)) {
			FD_SET(fd, wfd);
			i++;
		}
	}

	return i;
}


/** Writes pollfds (file descriptor and desired poll events) into the passed
 * array for all handles that wait for events.
 *
 * @param mhdl a multihandle containing N parallel requests
 * @param pollfds the pollfds returned by rc_async_get_pollfds().
 * @param pollfds_len the number of entries in pollfds.
 * @return the number of written pollfds.
 */
int
rc_multi_get_pollfds(struct rc_multihandle *mhdl, struct pollfd *pollfds,
		unsigned pollfds_len)
{
	int fd;
	short events;
	unsigned i = 0;
	struct pollfd *pfd;
	struct rc_async_handle_list_member *iter;

	if (!mhdl || !pollfds)
		return 0;

	for (iter = mhdl->next; iter && i < pollfds_len; iter = iter->next) {
		fd = rc_async_get_fd(iter->hdl);
		events = rc_async_get_events(iter->hdl);

		if (!events)
			continue;

		pfd = &pollfds[i];

		pfd->fd = fd;
		pfd->revents = 0;
		pfd->events = events;

		i++;
	}

	return i;
}


/** Processes all the async handles to the next step.
 * Checks all handles for timeouts.
 *
 * @param mhdl a multihandle containing N parallel requests.
 * @return the number of finished handles.
 */
int
rc_multi_process(struct rc_multihandle *mhdl)
{
	struct rc_async_handle_list_member *iter;
	int ready = 0;

	if (!mhdl)
		return 0;

	for (iter = mhdl->next; iter; iter = iter->next) {
		/* Pretend that read and write is possible for all handles */
		ready += rc_async_process_handle(iter->hdl, POLLIN | POLLOUT);
	}

	return ready;
}

/** Processes all the async handles to the next step as indicated by rfd and
 * wfd.  Checks all handles for timeouts.
 *
 * @param mhdl a multihandle containing N parallel requests.
 * @param rfd fd_set indicating file descriptors ready to read.
 * @param wfd fd_set indicating file descriptors ready to write.
 * @return the number of finished handles.
 */
int
rc_multi_process_fd_set(struct rc_multihandle *mhdl,
		fd_set* rfd, fd_set* wfd)
{
	struct rc_async_handle_list_member *iter;
	int ready = 0;
	short revents;
	int fd;

	if (!mhdl)
		return 0;

	for (iter = mhdl->next; iter; iter = iter->next) {
		fd = rc_async_get_fd(iter->hdl);
		revents = 0;
		revents |= !rfd || FD_ISSET(fd, rfd) ? POLLIN : 0;
		revents |= !wfd || FD_ISSET(fd, wfd) ? POLLOUT : 0;

		ready += rc_async_process_handle(iter->hdl, revents);
	}

	return ready;
}


static short
find_pollfd_revents(struct rc_async_handle *hdl,
		struct pollfd *pollfds, unsigned pollfds_len)
{
	int fd = rc_async_get_fd(hdl);
	unsigned i;

	if (!pollfds || fd < 0)
		return POLLIN | POLLOUT;

	for (i = 0; i < pollfds_len; i++) {
		if (fd == pollfds[i].fd)
			return pollfds[i].revents;
	}

	return POLLIN | POLLOUT;
}


/** Processes all the async handles to the next step if their pollfd demands so.
 * Checks all handles for timeouts.
 *
 * @param mhdl a multihandle containing N parallel requests.
 * @param pollfds the pollfds returned by rc_async_get_pollfds().
 * @param pollfds_len the number of entries in pollfds.
 * @return the number of finished handles, -1 on error.
 */
int
rc_multi_process_pollfds(struct rc_multihandle *mhdl,
		struct pollfd *pollfds, unsigned pollfds_len)
{
	struct rc_async_handle_list_member *iter;
	int ready = 0;
	short revents;

	if (!mhdl)
		return 0;

	/*
	 * TODO: this scales with n^2, but is preferable to try_receive()ing,
	 * invoking n syscalls. Make this more performant if necessary.
	 */
	for (iter = mhdl->next; iter; iter = iter->next) {
		revents = find_pollfd_revents(iter->hdl, pollfds, pollfds_len);

		ready += rc_async_process_handle(iter->hdl, revents);
	}

	return ready;
}
