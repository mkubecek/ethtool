/*
 * fec.c - netlink implementation of private flags commands
 *
 * Implementation of "ethtool --show-fec <dev>" and
 * "ethtool --set-fec <dev> ..."
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>

#include "../internal.h"
#include "../common.h"
#include "netlink.h"
#include "strset.h"
#include "bitset.h"
#include "parser.h"

/* FEC_GET */

static void fec_dump_cb(unsigned int idx, const char *name, bool val,
			void *data)
{
	bool *supported = data;
	char buff[16];

	if (!name) {
		snprintf(buff, sizeof(buff) - 1, "bit%u", idx);
		name = buff;
	}
	if (*supported || val)
		printf(" %s", name);
}

int fec_reply_cb(const struct nlmsghdr *nlhdr, void *data)
{
	const struct nlattr *tb[ETHTOOL_A_FEC_MAX + 1] = {};
	DECLARE_ATTR_TB_INFO(tb);
	const struct stringset *mode_names = NULL;
	struct nl_context *nlctx = data;
	bool supported;
	bool silent;
	int err_ret;
	int ret;

	silent = nlctx->is_dump || nlctx->is_monitor;
	err_ret = silent ? MNL_CB_OK : MNL_CB_ERROR;

	ret = mnl_attr_parse(nlhdr, GENL_HDRLEN, attr_cb, &tb_info);
	if (ret < 0 || !tb[ETHTOOL_A_FEC_MODES])
		return err_ret;
	nlctx->devname = get_dev_name(tb[ETHTOOL_A_FEC_HEADER]);
	if (!dev_ok(nlctx))
		return MNL_CB_OK;

	if (bitset_is_compact(tb[ETHTOOL_A_FEC_MODES])) {
		ret = netlink_init_ethnl2_socket(nlctx);
		if (ret < 0)
			return err_ret;
		mode_names = perdev_stringset(nlctx->devname, ETH_SS_FEC_MODES,
					      nlctx->ethnl2_socket);
	}

	if (silent)
		putchar('\n');
	printf("FEC parameters for %s:\n", nlctx->devname);
	printf("Configured FEC encodings:");
	supported = true;
	ret = walk_bitset(tb[ETHTOOL_A_FEC_MODES], mode_names,
			  fec_dump_cb, &supported);
	putchar('\n');
	if (ret < 0)
		return err_ret;

	printf("Active FEC encodings:");
	supported = false;
	ret = walk_bitset(tb[ETHTOOL_A_FEC_MODES], mode_names,
			  fec_dump_cb, &supported);
	putchar('\n');
	if (ret < 0)
		return err_ret;

	return MNL_CB_OK;
}

int nl_gfec(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_socket *nlsk = nlctx->ethnl_socket;
	int ret;

	ret = nlsock_prep_get_request(nlsk, ETHTOOL_MSG_FEC_GET,
				      ETHTOOL_A_FEC_HEADER, 0);
	if (ret < 0)
		return ret;
	return nlsock_send_get_request(nlsk, fec_reply_cb);
}

/* FEC_SET */

static const struct bitset_parser_data encoding_parser_data = {
	.force_hex	= false,
	.no_mask	= true,
};

static const struct param_parser sfec_params[] = {
	{
		.arg		= "encoding",
		.type		= ETHTOOL_A_FEC_MODES,
		.handler	= nl_parse_bitset,
		.handler_data	= &encoding_parser_data,
		.min_argc	= 1,
	},
};

int nl_sfec(struct cmd_context *ctx)
{
	struct nl_context *nlctx = ctx->nlctx;
	struct nl_msg_buff *msgbuff;
	struct nl_socket *nlsk;
	int ret;

	nlctx->cmd = "--set-fec";
	nlctx->argp = ctx->argp;
	nlctx->argc = ctx->argc;
	nlctx->devname = ctx->devname;
	nlsk = nlctx->ethnl_socket;
	msgbuff = &nlsk->msgbuff;

	ret = msg_init(nlctx, msgbuff, ETHTOOL_MSG_FEC_SET,
		       NLM_F_REQUEST | NLM_F_ACK);
	if (ret < 0)
		return 2;
	if (ethnla_fill_header(msgbuff, ETHTOOL_A_FEC_HEADER,
			       ctx->devname, 0))
		return -EMSGSIZE;

	ret = nl_parser(nlctx, sfec_params, NULL, PARSER_GROUP_NONE);
	if (ret < 0)
		return -EINVAL;

	ret = nlsock_sendmsg(nlsk, NULL);
	if (ret < 0)
		return 2;
	ret = nlsock_process_reply(nlsk, nomsg_reply_cb, nlctx);
	if (ret == 0)
		return 0;
	else
		return nlctx->exit_code ?: 1;
}
