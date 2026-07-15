# frozen_string_literal: true

require 'spec_helper_acceptance'

# CRS v4 support (MODULES-11857). On modern Enterprise Linux (EL10) there is no
# mod_security_crs package, so CRS is deployed via crs_source => path (pre-staged
# directory) or archive (fetched from a configurable, e.g. internal-mirror, URL).
# A minimal self-contained CRS fixture is built on the target so the test needs
# no internet access for the rule content.
describe 'apache::mod::security CRS v4', if: (os[:family].include?('redhat') && os[:release].to_i >= 10) do
  before(:all) do
    # The module does not manage the ModSecurity engine on EL10; provide it from EPEL.
    run_shell('rpm -q epel-release || dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm')
    run_shell('dnf install -y mod_security')

    # Minimal but valid CRS v4 layout for crs_source => path.
    run_shell('mkdir -p /opt/crs/rules')
    run_shell(%q(printf 'SecDefaultAction "phase:1,pass,log"\n' > /opt/crs/crs-setup.conf))
    run_shell(%q(printf 'SecRule ARGS "@rx evilpattern" "id:9001,phase:2,deny,status:403,log"\n' > /opt/crs/rules/REQUEST-901-TEST.conf))

    # A tarball standing in for an internal mirror, unpacking to the versioned
    # coreruleset-<version>/ dir with crs-setup.conf.example, as upstream ships.
    run_shell('mkdir -p /tmp/crsbuild/coreruleset-9.9.9/rules /var/www/mirror')
    run_shell('cp /opt/crs/crs-setup.conf /tmp/crsbuild/coreruleset-9.9.9/crs-setup.conf.example')
    run_shell('cp /opt/crs/rules/REQUEST-901-TEST.conf /tmp/crsbuild/coreruleset-9.9.9/rules/')
    run_shell('tar -C /tmp/crsbuild -czf /var/www/mirror/crs.tar.gz coreruleset-9.9.9')
  end

  context 'crs_source => path' do
    pp = <<-MANIFEST
      class { 'apache': }
      class { 'apache::mod::security':
        crs_source => 'path',
        crs_path   => '/opt/crs',
      }
    MANIFEST

    it 'applies idempotently' do
      idempotent_apply(pp)
    end

    describe file('/etc/httpd/modsecurity.d/security_crs_v4.conf') do
      it { is_expected.to be_file }
      its(:content) { is_expected.to match(%r{IncludeOptional /opt/crs/crs-setup\.conf}) }
      its(:content) { is_expected.to match(%r{IncludeOptional /opt/crs/rules/\*\.conf}) }
    end

    describe command('apachectl configtest') do
      its(:exit_status) { is_expected.to eq 0 }
    end
  end

  context 'crs_source => archive' do
    pp = <<-MANIFEST
      class { 'apache': }
      class { 'apache::mod::security':
        crs_source         => 'archive',
        crs_archive_source => 'file:///var/www/mirror/crs.tar.gz',
        crs_version        => '9.9.9',
      }
    MANIFEST

    it 'applies idempotently' do
      idempotent_apply(pp)
    end

    # Extracted to the versioned dir and crs-setup.conf created from the example.
    describe file('/usr/share/coreruleset-9.9.9/crs-setup.conf') do
      it { is_expected.to be_file }
    end

    describe file('/etc/httpd/modsecurity.d/security_crs_v4.conf') do
      its(:content) { is_expected.to match(%r{IncludeOptional /usr/share/coreruleset-9\.9\.9/crs-setup\.conf}) }
      its(:content) { is_expected.to match(%r{IncludeOptional /usr/share/coreruleset-9\.9\.9/rules/\*\.conf}) }
    end

    describe command('apachectl configtest') do
      its(:exit_status) { is_expected.to eq 0 }
    end
  end
end
