<?php

/*
 * Copyright (C) 2023-2024 Deciso B.V.
 * Copyright (C) 2018 Michael Muenz <m.muenz@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

function amneziawg_enabled()
{
    return (string)(new \OPNsense\AmneziaWG\General())->enabled == '1';
}

function amneziawg_services()
{
    $services = [];

    if (!amneziawg_enabled()) {
        return $services;
    }

    foreach ((new OPNsense\AmneziaWG\Server())->servers->server->iterateItems() as $key => $node) {
        if (!empty((string)$node->enabled)) {
            $services[] = [
                'description' => 'AmneziaWG ' . htmlspecialchars($node->name),
                'configd' => [
                    'start' => ["amneziawg start {$key}"],
                    'restart' => ["amneziawg restart {$key}"],
                    'stop' => ["amneziawg stop {$key}"],
                ],
                'name' => 'amneziawg',
                'nocheck' => true,
                'id' => $key,
            ];
        }
    }

    return $services;
}

function amneziawg_syslog()
{
    return [
        'amneziawg' => ['facility' => ['amneziawg']]
    ];
}

function amneziawg_interfaces()
{
    $interfaces = [];

    if (!amneziawg_enabled()) {
        return $interfaces;
    }

    $interfaces['amneziawg'] = [
        'descr' => gettext('AmneziaWG (Group)'),
        'if' => 'amneziawg',
        'virtual' => true,
        'enable' => true,
        'type' => 'group',
        'networks' => [],
    ];

    return $interfaces;
}

function amneziawg_xmlrpc_sync()
{
    $result = [];

    $result['id'] = 'amneziawg';
    $result['section'] = 'OPNsense.amneziawg';
    $result['description'] = gettext('AmneziaWG');
    $result['services'] = ['amneziawg'];

    return [$result];
}

function amneziawg_devices()
{
    $names = [];
    foreach ((new OPNsense\AmneziaWG\Server())->servers->server->iterateItems() as $key => $node) {
        if (!empty((string)$node->enabled)) {
            $names[(string)$node->interface] = [
                'descr' => sprintf('%s (AmneziaWG - %s)', (string)$node->interface, (string)$node->name),
                'ifdescr' => (string)$node->name,
                'name' => (string)$node->interface
            ];
        }
    }
    return [[
        'function' => 'amneziawg_prepare', /* XXX only (empty) device creation */
        'configurable' => false,
        'pattern' => '^awg',
        'type' => 'amneziawg',
        'volatile' => true,
        'names' => $names,
    ]];
}

function amneziawg_prepare($device)
{
    foreach ((new OPNsense\AmneziaWG\Server())->servers->server->iterateItems() as $node) {
        if ($device != (string)$node->interface) {
            continue;
        }

        /* deleting the stat file marks the interface for eventual reconfiguration */
        @unlink((string)$node->statFilename);

        if (!does_interface_exist($device)) {
            mwexecf('/sbin/ifconfig amn create name %s', $device);
            mwexecf('/sbin/ifconfig %s group amneziawg', $device);
        }

        return $device;
    }

    return null;
}

function amneziawg_configure()
{
    return [
        'newwanip' => ['amneziawg_sync'],
        'vpn' => ['amneziawg_configure_do'],
    ];
}

function amneziawg_configure_do($verbose = false)
{
    if (!amneziawg_enabled()) {
        return;
    }

    service_log('Configuring AmneziaWG VPN...', $verbose);

    configd_run('amneziawg configure');

    service_log("done.\n", $verbose);
}

function amneziawg_sync($verbose = false)
{
    if (!amneziawg_enabled()) {
        return;
    }

    $instances = [];
    foreach ((new OPNsense\AmneziaWG\Server())->servers->server->iterateItems() as $node) {
        if (!empty((string)$node->enabled)) {
            $instances[(string)$node->interface] = (string)$node->cnfFilename;
        }
    }

    if (!count($instances)) {
        return;
    }

    service_log('Synchronizing AmneziaWG VPN...', $verbose);

    foreach ($instances as $device => $config) {
        mwexecf('/usr/local/bin/awg syncconf %s %s', [$device, $config]);
    }

    service_log("done.\n", $verbose);
}
