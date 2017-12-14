/*	ptunnel.h
	ptunnel is licensed under the BSD license:
	
	Copyright (c) 2004-2011, Daniel Stoedle <daniels@cs.uit.no>,
	Yellow Lemon Software. All rights reserved.
	
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	- Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.

	- Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.

	- Neither the name of the Yellow Lemon Software nor the names of its
	  contributors may be used to endorse or promote products derived from this
	  software without specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
		
	Contacting the author:
	You can get in touch with me, Daniel St�dle (that's the Norwegian letter oe,
	in case your text editor didn't realize), here: <daniels@cs.uit.no>
	
	The official ptunnel website is here:
	<http://www.cs.uit.no/~daniels/PingTunnel/>
	
	Note that the source code is best viewed with tabs set to 4 spaces.
*/

#ifndef PING_TUNNEL_H
#define PING_TUNNEL_H 1

//	Includes
#ifndef WIN32
#include <sys/unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <errno.h>
#include <net/ethernet.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#endif /* !WIN32 */
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <pcap.h>

#include "pkt.h"
#include "pdesc.h"
#include "challenge.h"

/*	pt_thread_info_t: A simple (very simple, in fact) structure that allows us
	to pass an arbitrary number of params to the threads we create. Currently,
	that's just one single parameter: The socket which the thread should listen
	to.
*/
typedef struct {
	int
		sock;
} pt_thread_info_t;

/*	pqueue_elem_t: An queue element in the pqueue structure (below).
*/
typedef struct pqueue_elem_t {
	int
		bytes;		// size of data buffer
	struct pqueue_elem_t
		*next;		// next queue element (if any)
	char
		data[0];	// data (duh!)
} pqueue_elem_t;


/*	pqueue_t: A simple queue strucutre.
*/
typedef struct {
	pqueue_elem_t
		*head,
		*tail;
	int
		elems;
} pqueue_t;

/*	pcap_info_t: Structure to hold information related to packet capturing.
*/
typedef struct {
	pcap_t
		*pcap_desc;
	struct bpf_program
		fp;		//	Compiled filter program
	uint32_t
		netp,
		netmask;
	char
		*pcap_err_buf,	//	Buffers for error and packet info
		*pcap_data_buf;
	pqueue_t
		pkt_q;		//	Queue of packets to process
} pcap_info_t;


//	Prototypes (sorry about the long lines..)
	void*		pt_proxy(void *args);
	void		pcap_packet_handler(u_char *refcon, const struct pcap_pkthdr *hdr, const u_char* pkt);
	void		handle_packet(char *buf, int bytes, int is_pcap, struct sockaddr_in *addr, int icmp_sock);

	proxy_desc_t*	create_and_insert_proxy_desc(uint16_t id_no, uint16_t icmp_id, int sock, struct sockaddr_in *addr, uint32_t dst_ip, uint32_t dst_port, uint32_t init_state, uint32_t type);
	void		remove_proxy_desc(proxy_desc_t *cur, proxy_desc_t *prev);

	void		pt_forwarder(void);

	void		print_statistics(xfer_stats_t *xfer, int is_continuous);
	int			queue_packet(int icmp_sock, uint8_t type, char *buf, int num_bytes, uint16_t id_no, uint16_t icmp_id, uint16_t *seq, icmp_desc_t ring[], int *insert_idx, int *await_send, uint32_t ip, uint32_t port, uint32_t state, struct sockaddr_in *dest_addr, uint16_t next_expected_seq, int *first_ack, uint16_t *ping_seq);
	uint32_t	send_packets(forward_desc_t *ring[], int *xfer_idx, int *await_send, int *sock);
	void		handle_data(icmp_echo_packet_t *pkt, int total_len, forward_desc_t *ring[], int *await_send, int *insert_idx, uint16_t *next_expected_seq);
	void		handle_ack(uint16_t seq_no, icmp_desc_t ring[], int *packets_awaiting_ack, int one_ack_only, int insert_idx, int *first_ack, uint16_t *remote_ack, int is_pcap);
	forward_desc_t*	create_fwd_desc(uint16_t seq_no, uint32_t data_len, char *data);
	void		init_ip_packet(ip_packet_t *packet, uint16_t id, uint16_t frag_offset, uint16_t pkt_len, uint8_t ttl, uint32_t src_ip, uint32_t dst_ip, bool is_last_frag, bool dont_frag);
	uint16_t	calc_ip_checksum(ip_packet_t *pkt);
	uint16_t	calc_icmp_checksum(uint16_t *data, int bytes);

	challenge_t*	generate_challenge(void);
	void		generate_response(challenge_t *challenge);
	int		validate_challenge(challenge_t *local, challenge_t *remote);

	void		send_termination_msg(proxy_desc_t *cur, int icmp_sock);

	char*	f_inet_ntoa(uint32_t ip);
	void	pt_log(int level, const char *fmt, ...);
	double	time_as_double(void);
#endif
