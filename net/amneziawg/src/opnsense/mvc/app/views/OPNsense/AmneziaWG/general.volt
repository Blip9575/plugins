{#
 # Copyright (c) 2014-2026 Deciso B.V.
 # Copyright (c) 2018 Michael Muenz <m.muenz@gmail.com>
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without modification,
 # are permitted provided that the following conditions are met:
 #
 # 1.  Redistributions of source code must retain the above copyright notice,
 #     this list of conditions and the following disclaimer.
 #
 # 2.  Redistributions in binary form must reproduce the above copyright notice,
 #     this list of conditions and the following disclaimer in the documentation
 #     and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #}

<script>
    $( document ).ready(function() {
        const data_get_map = {'frm_general_settings':"/api/amneziawg/general/get"};
        let configbuilder_reference = null;
        mapDataToFormUI(data_get_map).done(function(data){
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });

        const grid_peers = $("#{{formGridAmneziaWGClient['table_id']}}").UIBootgrid({
            search: '/api/amneziawg/client/search_client',
            get: '/api/amneziawg/client/get_client/',
            set: '/api/amneziawg/client/set_client/',
            add: '/api/amneziawg/client/add_client/',
            del: '/api/amneziawg/client/del_client/',
            toggle: '/api/amneziawg/client/toggle_client/',
            options: {
                initialSearchPhrase: getUrlHash('search'),
                requestHandler: function(request){
                    if ( $('#server_filter').val().length > 0) {
                        request['servers'] = $('#server_filter').val();
                    }
                    return request;
                }
            },
            commands: {
                show_peer: {
                    filter: (cell) => !!cell.getData().privkey,
                    classname: "fa fa-fw fa-qrcode",
                    title: "{{ lang._('Open in peer generator') }}",
                    sequence: 1000,
                    method: function(event, cell) {
                        configbuilder_reference = cell.getData();
                        $('a[href="#configbuilder"]').tab('show');
                    }
                }
            },
        });
        grid_peers.on("loaded.rs.jquery.bootgrid", function (e){
            // reload servers before grid load
            if ($("#server_filter > option").length == 0) {
                ajaxGet('/api/amneziawg/client/list_servers', {}, function(data, status){
                    if (data.rows !== undefined) {
                        for (let i=0; i < data.rows.length ; ++i) {
                            let row = data.rows[i];
                            $("#server_filter").append($("<option/>").val(row.uuid).html(row.name));
                        }
                        $("#server_filter").selectpicker('refresh');
                    }
                });
            }
        });

        $("#{{formGridAmneziaWGServer['table_id']}}").UIBootgrid({
            search: '/api/amneziawg/server/search_server',
            get: '/api/amneziawg/server/get_server/',
            set: '/api/amneziawg/server/set_server/',
            add: '/api/amneziawg/server/add_server/',
            del: '/api/amneziawg/server/del_server/',
            toggle: '/api/amneziawg/server/toggle_server/',
            options: {
                formatters: {
                    /* the list holds the stored key of the profile, show its label and nothing for none */
                    awg2profile: function (column, row) {
                        const labels = {
                            random: 'Random', dns: 'DNS (53)', ntp: 'NTP (123)', quic: 'QUIC (443)', sip: 'SIP (5060)',
                            stun: 'STUN (3478)'
                        };
                        return labels[row[column.id]] || '';
                    },
                    awg3profile: function (column, row) {
                        return row[column.id] === 'random' ? 'Random' : '';
                    }
                }
            }
        });

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function() {
                const dfObj = new $.Deferred();
                saveFormToEndpoint("/api/amneziawg/general/set", 'frm_general_settings', function(){
                    dfObj.resolve();
                });
                return dfObj;
            }
        });

        /**
         * Move keypair generation button inside the instance form and hook api event
         */
        $("#control_label_server\\.pubkey").append($("#keygen_div").detach().show());
        /**
         * Parameter generators on the labels of the AmneziaWG 2.0 and 3.x rows, like the keypair button. The gear of
         * AmneziaWG 2.0 replaces Jc, Jmin, Jmax, S1-S4 and H1-H4 with a new random profile for the protocol selected in
         * the row (Random imitates no protocol and clears I1-I5, a protocol also sets I1). The gear of AmneziaWG 3.x
         * generates a new header protection key and sets S1-S4 when they are empty or below the 12 it requires. None
         * generates nothing. Nothing is saved before the dialog is saved, but peers of this instance stop working with
         * changed values, so the dialog asks first when peers are selected and values would be replaced.
         */
        $("#control_label_server\\.awg2_profile").append($("#awg2gen_div").detach().show());
        $("#control_label_server\\.awg3_profile").append($("#awg3gen_div").detach().show());
        const awg_sync = function () {
            $("#awg2gen").prop('disabled', $("#server\\.awg2_profile").val() === 'none');
            $("#awg3gen").prop('disabled', $("#server\\.awg3_profile").val() === 'none');
        };
        $("#server\\.awg2_profile, #server\\.awg3_profile").on('change', awg_sync);
        $("#{{ formGridAmneziaWGServer['edit_dialog_id'] }}").on('shown.bs.modal', awg_sync);
        const awg_filled = function (fields) {
            return fields.some(function (field) {
                return String($("#server\\." + field).val() || '') !== '';
            });
        };
        const awg_generate = function (url, replaces) {
            const apply = function () {
                ajaxGet(url, {}, function (data, status) {
                    if (data.status && data.status === 'ok') {
                        $.each(data.params, function (field, value) {
                            /* the response is HTML escaped for the browser, I1 contains angle brackets */
                            $("#server\\." + field).val(htmlDecode(value));
                        });
                    }
                });
            };
            const peers = $("#server\\.peers").val();
            if (replaces && peers && peers.length > 0) {
                stdDialogConfirm(
                    "{{ lang._('Replace parameters') }}",
                    "{{ lang._('This instance has peers. They stop connecting until they use a new configuration with the new values. Replace the parameters?') }}",
                    "{{ lang._('Yes') }}", "{{ lang._('Cancel') }}", apply
                );
            } else {
                apply();
            }
        };
        $("#awg2gen").click(function () {
            const profile = $("#server\\.awg2_profile").val();
            if (profile && profile !== 'none') {
                awg_generate(
                    "/api/amneziawg/server/gen_params/" + profile,
                    awg_filled(['jc', 'jmin', 'jmax', 's1', 's2', 's3', 's4', 'h1', 'h2', 'h3', 'h4', 'i1', 'i2', 'i3', 'i4', 'i5'])
                );
            }
        });
        $("#awg3gen").click(function () {
            const profile = $("#server\\.awg3_profile").val();
            if (profile && profile !== 'none') {
                const prefixes = ['s1', 's2', 's3', 's4'];
                const need_prefixes = prefixes.some(function (field) {
                    const value = parseInt($("#server\\." + field).val(), 10);
                    return isNaN(value) || value < 12;
                });
                awg_generate(
                    "/api/amneziawg/server/gen_params3/" + profile + "/" + (need_prefixes ? '1' : '0'),
                    awg_filled(['headerprotectionkey']) || (need_prefixes && awg_filled(prefixes))
                );
            }
        });
        $("#keygen").click(function(){
            ajaxGet("/api/amneziawg/server/key_pair", {}, function(data, status){
                if (data.status && data.status === 'ok') {
                    $("#server\\.pubkey").val(data.pubkey);
                    $("#server\\.privkey").val(data.privkey);
                }
            });
        })
        $("#control_label_client\\.psk").append($("#pskgen_div").detach().show());
        $("#pskgen").click(function(){
            ajaxGet("/api/amneziawg/client/psk", {}, function(data, status){
                if (data.status && data.status === 'ok') {
                    $("#client\\.psk").val(data.psk);
                }
            });
        })

        /**
         * Quick instance filter on top
         */
        $("#filter_container").detach().insertAfter('#{{formGridAmneziaWGClient["table_id"]}}-header .search');
        $("#server_filter").change(function(){
            $('#{{formGridAmneziaWGClient['table_id']}}').bootgrid('reload');
        });

        /**
         * Build the peer config for the peer generator
         */
        function buildPeerConfig(data)
        {
            let rows = [];
            rows.push('[Interface]');
            rows.push('PrivateKey = ' + data.privkey);
            if (data.address) {
                rows.push('Address = ' + data.address);
            }
            if (data.peer_dns) {
                rows.push('DNS = ' + data.peer_dns);
            }
            if (data.mtu) {
                rows.push('MTU = ' + data.mtu);
            }
            $.each(data.awg || {}, function (key, value) {
                rows.push(key + ' = ' + htmlDecode(value));
            });
            rows.push('');
            rows.push('[Peer]');
            rows.push('PublicKey = ' + data.pubkey);
            if (data.psk) {
                rows.push('PresharedKey = ' + data.psk);
            }
            rows.push('Endpoint = ' + data.endpoint);
            rows.push('AllowedIPs = ' + data.allowedips);
            if (data.keepalive) {
                rows.push('PersistentKeepalive = ' + data.keepalive);
            }
            return rows.join("\n");
        }

        /**
         * Load instance information for the peer generator
         */
        function configbuilder_load_server(server_id, callback, update_address = true)
        {
            ajaxGet('/api/amneziawg/client/get_server_info/' + server_id, {}, function(data, status) {
                if (data.status === 'ok') {
                    let endpoint = $("#configbuilder\\.endpoint");
                    let peer_dns = $("#configbuilder\\.peer_dns");
                    let allowed_ips = $("#configbuilder\\.tunneladdress");

                    if (update_address) {
                        $("#configbuilder\\.address").val(data.address);
                    }

                    peer_dns
                        .val(data.peer_dns)
                        .data('org-value', data.peer_dns);

                    endpoint
                        .val(data.endpoint)
                        .data('org-value', data.endpoint)
                        .data('mtu', data.mtu)
                        .data('pubkey', data.pubkey)
                        .data('awg', data.awg);

                    const allowed_ips_value = data.allowed_ips || "0.0.0.0/0,::/0";
                    allowed_ips
                        .val(allowed_ips_value)
                        .data('org-value', allowed_ips_value);

                    if (callback) {
                        callback();
                    }

                    endpoint.change();
                }
            });
        }

        /**
         * Toggle peer generator reference mode
         */
        function configbuilder_set_reference_mode(enabled)
        {
            $("#configbuilder\\.name").prop("disabled", enabled);

            [
                "servers",
                "endpoint",
                "peer_dns",
                "tunneladdress",
                "keepalive",
                "pubkey",
                "privkey",
                "psk",
                "address",
                "store_privkey",
                "actions"
            ].forEach(function(field) {
                $("#row_configbuilder\\." + field).toggle(!enabled);
            });

            $("#pskgen_cb").toggle(!enabled);
        }

        /**
         * Load an existing peer into the peer generator
         */
        function configbuilder_load_reference(row)
        {
            const server_id = row.servers;

            $("#configbuilder\\.servers")
                .val(server_id)
                .selectpicker('refresh');

            $("#configbuilder\\.name").val(row.name);
            $("#configbuilder\\.pubkey").val(row.pubkey);
            $("#configbuilder\\.privkey").val(row.privkey);
            $("#configbuilder\\.psk").val(row.psk);
            $("#configbuilder\\.address").val(row.tunneladdress);
            $("#configbuilder\\.keepalive").val(row.keepalive);

            configbuilder_load_server(server_id, function() {
                configbuilder_set_reference_mode(true);
            }, false);
        }

        /**
         * Peer generator tab hooks
         */
        $("#control_label_configbuilder\\.psk").append($("#pskgen_cb_div").detach().show());
        $("#pskgen_cb").click(function(){
            ajaxGet("/api/amneziawg/client/psk", {}, function(data, status){
                if (data.status && data.status === 'ok') {
                    $("#configbuilder\\.psk").val(data.psk).change();
                }
            });
        })
        $("#configbuilder\\.output").css('max-width', '100%');
        $("#configbuilder\\.output").css('height', '256px');
        $("#configbuilder\\.output").on('input', function() {
            $("#configbuilder\\.qrcode").empty().qrcode($(this).val());
        });

        $("#configbuilder\\.servers").change(function(){
            configbuilder_load_server($(this).val());
        });

        $("#btn_configbuilder_cancel").click(function() {
            $('a[href="#peers"]').tab('show');
        });

        $("#btn_configbuilder_save").click(function(){
            if (configbuilder_reference !== null) {
                return;
            }
            let instance_id = $("#configbuilder\\.servers").val();
            let endpoint = $("#configbuilder\\.endpoint");
            let peer_dns = $("#configbuilder\\.peer_dns");
            let allowed_ips = $("#configbuilder\\.tunneladdress");
            let peer = {
                configbuilder: {
                    enabled: '1',
                    name: $("#configbuilder\\.name").val(),
                    pubkey: $("#configbuilder\\.pubkey").val(),
                    privkey: $("#configbuilder\\.store_privkey").prop("checked")
                        ? $("#configbuilder\\.privkey").val()
                        : '',
                    psk: $("#configbuilder\\.psk").val(),
                    tunneladdress: $("#configbuilder\\.address").val(),
                    keepalive: $("#configbuilder\\.keepalive").val(),
                    server: instance_id,
                    endpoint: endpoint.val()
                }
            };
            ajaxCall('/api/amneziawg/client/add_client_builder', peer, function(data, status) {
                if (data.validations) {
                    if (data.validations['configbuilder.tunneladdress']) {
                        /*
                         * tunnel address for the client is this peers address, since we remap these
                         * in the form, we should remap the errors as well.
                         */
                        data.validations['configbuilder.address'] = data.validations['configbuilder.tunneladdress'];
                        delete data.validations['configbuilder.tunneladdress'];
                    }
                    handleFormValidation("frm_config_builder", data.validations);
                } else {
                    $(document).trigger("settings-changed");
                    if (
                        endpoint.val() != endpoint.data('org-value') ||
                        peer_dns.val() != peer_dns.data('org-value') ||
                        allowed_ips.val() != allowed_ips.data('org-value')
                    ) {
                        let param = {
                            'server': {
                                'endpoint': endpoint.val(),
                                'peer_dns': peer_dns.val(),
                                'allowed_ips': allowed_ips.val()
                            }
                        };
                        ajaxCall('/api/amneziawg/server/set_server/' + instance_id, param, function(data, status){
                            configbuilder_new();
                        });
                    } else {
                        configbuilder_new();
                    }
                }
            });
        });
        $('input[id ^= "configbuilder\\."]').change(configbuilder_update_config);
        $('select[id ^= "configbuilder\\."]').change(configbuilder_update_config);

        function configbuilder_new()
        {
            configbuilder_reference = null;
            configbuilder_set_reference_mode(false);

            mapDataToFormUI({'frm_config_builder':"/api/amneziawg/client/get_client_builder"}).done(function(data){
                formatTokenizersUI();
                $('.selectpicker').selectpicker('refresh');
                // Private key storage is intentionally opt-in to preserve existing behavior.
                $("#configbuilder\\.store_privkey").prop("checked", false);
                ajaxGet("/api/amneziawg/server/key_pair", {}, function(data, status){
                    if (data.status && data.status === 'ok') {
                        $("#configbuilder\\.pubkey").val(data.pubkey);
                        $("#configbuilder\\.privkey").val(data.privkey).change();
                    }
                });
                clearFormValidation("frm_config_builder");
            });
        }

        function configbuilder_update_config()
        {
            const config = buildPeerConfig({
                privkey: $("#configbuilder\\.privkey").val(),
                address: $("#configbuilder\\.address").val(),
                peer_dns: $("#configbuilder\\.peer_dns").val(),
                mtu: $("#configbuilder\\.endpoint").data('mtu'),
                pubkey: $("#configbuilder\\.endpoint").data('pubkey'),
                awg: $("#configbuilder\\.endpoint").data('awg'),
                psk: $("#configbuilder\\.psk").val(),
                endpoint: $("#configbuilder\\.endpoint").val(),
                allowedips: $("#configbuilder\\.tunneladdress").val(),
                keepalive: $("#configbuilder\\.keepalive").val()
            });

            $("#configbuilder\\.output").val(config).trigger('input');
        }

        const $apply_container = $("#reconfigureAct").closest(".alert.content-box");

        $('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
            if (e.target.id == 'tab_configbuilder') {
                if (configbuilder_reference !== null) {
                    configbuilder_load_reference(configbuilder_reference);
                    $apply_container.hide();
                } else {
                    configbuilder_new();
                    $apply_container.show();
                }
                $('#frm_general_settings').parent().hide();
            } else {
                configbuilder_reference = null;
                $apply_container.show();
                $('#{{formGridAmneziaWGClient['table_id']}}').bootgrid('reload');
                $('#frm_general_settings').parent().show();
            }
        });

        // update history on tab state and implement navigation
        if(window.location.hash != "") {
            $('a[href="' + window.location.hash + '"]').click()
        }
        $('.nav-tabs a').on('shown.bs.tab', function (e) {
            history.pushState(null, null, e.target.hash);
        });
        $(window).on('hashchange', function(e) {
            $('a[href="' + window.location.hash + '"]').click()
        });
    });
</script>

<!-- Navigation bar -->
<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" id="tab_instances" href="#instances">{{ lang._('Instances') }}</a></li>
    <li><a data-toggle="tab" id="tab_peers" href="#peers">{{ lang._('Peers') }}</a></li>
    <li><a data-toggle="tab" id="tab_configbuilder" href="#configbuilder">{{ lang._('Peer generator') }}</a></li>
</ul>

<div class="tab-content content-box tab-content">
    <div id="peers" class="tab-pane fade in">
        <span id="pskgen_div" style="display:none" class="pull-right">
            <button id="pskgen" type="button" class="btn btn-secondary" title="{{ lang._('Generate new psk.') }}" data-toggle="tooltip">
              <i class="fa fa-fw fa-gear"></i>
            </button>
        </span>
        <div class="hidden">
            <!-- filter per server container -->
            <div id="filter_container" class="btn-group">
                <select id="server_filter"  data-title="{{ lang._('Instances') }}" class="selectpicker" data-live-search="true" data-size="5"  multiple data-width="200px">
                </select>
            </div>
        </div>
        {{ partial('layout_partials/base_bootgrid_table', formGridAmneziaWGClient + {'command_width':'120'}) }}
    </div>
    <div id="instances" class="tab-pane fade in active">
        <span id="keygen_div" style="display:none" class="pull-right">
            <button id="keygen" type="button" class="btn btn-secondary" title="{{ lang._('Generate new keypair.') }}" data-toggle="tooltip">
              <i class="fa fa-fw fa-gear"></i>
            </button>
        </span>
        <span id="awg2gen_div" style="display:none" class="pull-right">
            <button id="awg2gen" type="button" class="btn btn-secondary" title="{{ lang._('Generate a new AmneziaWG 2.0 profile for the selected protocol. This replaces Jc, Jmin, Jmax, S1-S4 and H1-H4 and sets I1-I5. Select Random or a protocol first.') }}" data-toggle="tooltip">
              <i class="fa fa-fw fa-gear"></i>
            </button>
        </span>
        <span id="awg3gen_div" style="display:none" class="pull-right">
            <button id="awg3gen" type="button" class="btn btn-secondary" title="{{ lang._('Generate a new header protection key for AmneziaWG 3.x and set S1-S4 when they are below 12. Select Random first.') }}" data-toggle="tooltip">
              <i class="fa fa-fw fa-gear"></i>
            </button>
        </span>
        {{ partial('layout_partials/base_bootgrid_table', formGridAmneziaWGServer)}}
    </div>
    <div id="configbuilder" class="tab-pane fade in">
        <span id="pskgen_cb_div" style="display:none" class="pull-right">
            <button id="pskgen_cb" type="button" class="btn btn-secondary" title="{{ lang._('Generate new psk.') }}" data-toggle="tooltip">
              <i class="fa fa-fw fa-gear"></i>
            </button>
        </span>
        {{ partial("layout_partials/base_form",['fields':formDialogConfigBuilder,'id':'frm_config_builder'])}}
    </div>
</div>
<div class="tab-content content-box tab-content __mt">
    {{ partial("layout_partials/base_form",['fields':generalForm,'id':'frm_general_settings'])}}
</div>
{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/amneziawg/service/reconfigure'}) }}
{{ partial("layout_partials/base_dialog",['fields':formDialogEditAmneziaWGClient,'id':formGridAmneziaWGClient['edit_dialog_id'],'label':lang._('Edit peer')])}}
{{ partial("layout_partials/base_dialog",['fields':formDialogEditAmneziaWGServer,'id':formGridAmneziaWGServer['edit_dialog_id'],'label':lang._('Edit instance')])}}
