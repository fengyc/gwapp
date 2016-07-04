# -*- coding:utf-8 -*-
# Copyright (c) 2016 Yingcai FENG
#
# 2016/7/4 fengyc: Create hooks.


HOOK_BEFORE_CONNECT = 'hook_before_connect'
HOOK_AFTER_CONNECT = 'hook_after_connect'
HOOK_BEFORE_AUTH = 'hook_before_auth'
HOOK_AFTER_AUTH = 'hook_after_auth'
HOOK_AFTER_AUTH_FAIL = 'hook_after_auth_fail'
HOOK_AFTER_AUTH_SUCCESS = 'hook_after_auth_success'


class Hook(object):
    pass