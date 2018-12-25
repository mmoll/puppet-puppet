aio = on_os_under_test.reject do |os, facts|
  ['FreeBSD', 'DragonFly', 'Windows'].include?(facts[:operatingsystem])
end.keys

add_custom_fact :rubysitedir, '/opt/puppetlabs/puppet/lib/ruby/site_ruby/2.1.0', :confine => aio

def unsupported_puppetmaster_osfamily(osfamily)
  ['Archlinux', 'windows', 'Suse'].include?(osfamily)
end
