/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

package format

type Interface interface {
	Add() error
	Get() error
	Update() error
	Delete() error
	Format() error
}
// TODO