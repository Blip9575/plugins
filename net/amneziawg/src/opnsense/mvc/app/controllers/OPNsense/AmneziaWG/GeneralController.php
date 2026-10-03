<?php

/*
 * Copyright (C) 2024 Deciso B.V.
 * Copyright (C) 2018 Michael Muenz <m.muenz@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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

namespace OPNsense\AmneziaWG;

class GeneralController extends \OPNsense\Base\IndexController
{
    protected function templateJSIncludes()
    {
        $result = parent::templateJSIncludes();
        $result[] = '/ui/js/qrcode.js';
        $result[] = '/ui/js/qrcode_UTF8.js';
        $result[] = '/ui/js/jquery.qrcode.js';
        return $result;
    }

    /**
     * version and build of the installed package, from the version file the package installs (product_version and
     * product_hash, the git hash of the plugins repository it was built from)
     */
    private function pluginVersion()
    {
        $info = json_decode((string)@file_get_contents('/usr/local/opnsense/version/amneziawg'), true);
        if (empty($info['product_version'])) {
            return '';
        }
        return $info['product_version'] . (!empty($info['product_hash']) ? ' (' . $info['product_hash'] . ')' : '');
    }

    public function indexAction()
    {
        $this->view->generalForm = $this->getForm("general");
        $this->view->amneziawgVersion = $this->pluginVersion();

        $this->view->formDialogEditAmneziaWGClient = $this->getForm("dialogEditAmneziaWGClient");
        $this->view->formGridAmneziaWGClient = $this->getFormGrid("dialogEditAmneziaWGClient");

        $this->view->formDialogEditAmneziaWGServer = $this->getForm("dialogEditAmneziaWGServer");
        $this->view->formGridAmneziaWGServer = $this->getFormGrid("dialogEditAmneziaWGServer");

        $this->view->formDialogConfigBuilder = $this->getForm("dialogConfigBuilder");
        $this->view->pick('OPNsense/AmneziaWG/general');
    }
}
