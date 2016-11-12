class puppet::server::authorization {
  ::puppet_authorization { "${::puppet::server::puppetserver_dir}/conf.d/auth.conf":
    version                => 1,
    allow_header_cert_info => $::puppet::server::http,
  }

  $puppetserver_authorization   = {
    'puppetlabs catalog'        => {
      match_request_path        => '^/puppet/v3/catalog/([^/]+)$',
      match_request_type        => 'regex',
      match_request_method      => ['get','post'],
      allow                     => $::puppet::auth_allowed,
      sort_order                => 500,
    },

    'puppetlabs certificate'    => {
      match_request_path        => '/puppet-ca/v1/certificate/',
      match_request_type        => 'path',
      match_request_method      => ['get'],
      allow_unauthenticated     => true,
      sort_order                => 500,
    },

    'puppetlabs crl'            => {
      match_request_path        => '/puppet-ca/v1/certificate_revocation_list/ca',
      match_request_type        => 'path',
      match_request_method      => ['get'],
      allow_unauthenticated     => true,
      sort_order                => 500,
    },

    'puppetlabs csr'            => {
      match_request_path        => '/puppet-ca/v1/certificate_request',
      match_request_type        => 'path',
      match_request_method      => ['get','put'],
      allow_unauthenticated     => true,
      sort_order                => 500,
    },

    'puppetlabs environments'   => {
      match_request_path        => '/puppet/v3/environments',
      match_request_type        => 'path',
      match_request_method      => ['get'],
      allow                     => ['*'],
      sort_order                => 500,
    },

    'puppetlabs resource type'  => {
      match_request_path        => '/puppet/v3/resource_type',
      match_request_type        => 'path',
      match_request_method      => ['get','post'],
      allow                     => ['*'],
      sort_order                => 500,
    },

    'puppetlabs file'           => {
      match_request_path        => '/puppet/v3/file',
      match_request_type        => 'path',
      allow                     => ['*'],
      sort_order                => 500,
    },

    'puppetlabs node'           => {
      match_request_path        => '^/puppet/v3/node/([^/]+)$',
      match_request_type        => 'regex',
      match_request_method      => ['get'],
      allow                     => $::puppet::auth_allowed,
      sort_order                => 500,
    },

    'puppetlabs report'         => {
      match_request_path        => '^/puppet/v3/report/([^/]+)$',
      match_request_type        => 'regex',
      match_request_method      => ['put'],
      allow                     => $::puppet::auth_allowed,
      sort_order                => 500,
    },

    'puppetlabs status'         => {
      match_request_path        => '/puppet/v3/status',
      match_request_type        => 'path',
      match_request_method      => ['get'],
      allow_unauthenticated     => true,
      sort_order                => 500,
    },

    'puppetlabs static file content' => {
      match_request_path        => '/puppet/v3/static_file_content',
      match_request_type        => 'path',
      match_request_method      => ['get'],
      allow                     => ['*'],
      sort_order                => 500,
    },

    'puppetlabs deny all'       => {
      match_request_path        => '/',
      match_request_type        => 'path',
      deny                      => ['*'],
      sort_order                => 999,
    },
  }

  if versioncmp($::puppet::server_puppetserver_version, '2.2') > 0 {
    if $::puppet::server_ca {
      if $::puppet::server::ca_auth_required == false {
        $certificate_authorization = {
          'certificate_status'  => {
            match_request_path    => '/certificate_status/',
            match_request_type    => 'path',
            match_request_method  => ['get','put', 'delete'],
            allow_unauthenticated => true,
            sort_order            => 200,
          },
          'certificate_statuses'    => {
            match_request_path    => '/certificate_statuses/',
            match_request_type    => 'path',
            match_request_method  => ['get'],
            allow_unauthenticated => true,
            sort_order            => 200,
          },
        }
      } else {
        $certificate_authorization = {
          'certificate_status'  => {
            match_request_path    => '/certificate_status/',
            match_request_type    => 'path',
            match_request_method  => ['get','put', 'delete'],
            allow                 => $::puppet::server::ca_client_whitelist,
            sort_order            => 200,
          },

          'certificate_statuses'    => {
            match_request_path    => '/certificate_statuses/',
            match_request_type    => 'path',
            match_request_method  => ['get'],
            allow                 => $::puppet::server::ca_client_whitelist,
            sort_order            => 200,
          },
        }
      }
    } else {
      $certificate_authorization = {}
    }

    $admin_authorization ={
      'environment-cache'  => {
        match_request_path    => '/environment-cache',
        match_request_type    => 'path',
        match_request_method  => ['delete'],
        allow                 => $::puppet::server::admin_api_whitelist,
        sort_order            => 200,
      },

      'jruby-pool'  => {
        match_request_path    => '/puppet-admin-api/v1/jruby-pool',
        match_request_type    => 'path',
        match_request_method  => ['get'],
        allow                 => $::puppet::server::admin_api_whitelist,
        sort_order            => 200,
      },
    }
  }

  $authorization_rules = merge($puppetserver_authorization, $certificate_authorization, $admin_authorization)

  create_resources(puppet::server::authorization::rule, $authorization_rules)
}
