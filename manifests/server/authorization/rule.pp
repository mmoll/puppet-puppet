define puppet::server::authorization::rule(
  $match_request_path,
  $match_request_type,
  $sort_order,
  $match_request_query_params = {},
  $match_request_method       = [],
  $allow_unauthenticated      = undef,
  $allow                      = undef,
  $deny                       = undef,
) {
  if $allow_unauthenticated != undef {
    ::puppet_authorization::rule { $name:
      path                  => "${::puppet::server::puppetserver_dir}/conf.d/auth.conf",
      match_request_path    => $match_request_path,
      match_request_type    => $match_request_type,
      match_request_method  => $match_request_method,
      allow_unauthenticated => $allow_unauthenticated,
      deny                  => $deny,
      sort_order            => $sort_order,
    }
  } else {
    ::puppet_authorization::rule { $name:
      path                 => "${::puppet::server::puppetserver_dir}/conf.d/auth.conf",
      match_request_path   => $match_request_path,
      match_request_type   => $match_request_type,
      match_request_method => $match_request_method,
      allow                => $allow,
      deny                 => $deny,
      sort_order           => $sort_order,
    }
  }
}
