require 'spec_helper_acceptance'

describe 'Scenario: install puppetserver (latest):' do
  before(:context) do
    if check_for_package(default, 'puppetserver')
      on(
        default,
        'rpm --erase puppetserver && ' \
        'rm -rf /etc/sysconfig/puppetserver /etc/puppetlabs/puppetserver && ' \
        'find /etc/puppetlabs/puppet/ssl/ -type f -delete'
      )
    end

    # puppetserver won't start with lower than 2GB memory
    memoryfree_mb = fact('memoryfree_mb').to_i
    raise 'At least 2048MB free memory required' if memoryfree_mb < 2048
  end

  let(:pp) do
    <<-EOS
    class { '::puppet':
      server                => true,
      server_foreman        => false,
      server_reports        => 'store',
      server_external_nodes => '',
    }
    EOS
  end

  it_behaves_like 'a idempotent resource'
end
