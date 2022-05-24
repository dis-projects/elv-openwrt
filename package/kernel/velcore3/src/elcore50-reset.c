// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2020 RnD Center "ELVEES", JSC
 */

#include <linux/err.h>
#include <linux/errno.h>
#include <linux/reset.h>

#include "elcore50-reset.h"

void elcore50_reset_fini(struct cluster_priv *drv_priv)
{
	if (drv_priv->resets)
		reset_control_assert(drv_priv->resets);
}

int elcore50_reset_init(struct cluster_priv *drv_priv)
{
	int ret;

	drv_priv->resets = devm_reset_control_array_get(drv_priv->dev, 1, 0);
	if (IS_ERR(drv_priv->resets)) {
		dev_warn(drv_priv->dev, "Failed to initialize resets\n");
		drv_priv->resets = NULL;
	}

	if (drv_priv->resets) {
		ret = reset_control_deassert(drv_priv->resets);
		if (ret)
			return ret;
	}

	return 0;
}
