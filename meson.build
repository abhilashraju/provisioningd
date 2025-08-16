project('provisioningd', 'cpp',default_options: ['c_std=c18','cpp_std=c++23','cpp_args=-Wno-subobject-linkage'])
reactor_dep=dependency('reactor')
boost_dep = dependency('boost', modules: ['url'], required: true)
openssl_dep = dependency('openssl', required: true)
sdeventplus_dep = dependency('sdeventplus')
sdbusplus_dep =dependency('sdbusplus')
executable('provisioningd',
  'src/provisioningd.cpp',
  install: true,
  include_directories:['src'],
  dependencies:[reactor_dep,boost_dep,openssl_dep,sdeventplus_dep,sdbusplus_dep],
  install_dir: '/usr/bin'
)

install_data('service/xyz.openbmc_project.Provisioning.service',
  install_dir: '/usr/lib/systemd/system'
)
install_data('service/xyz.openbmc_project.Provisioning.conf',
  install_dir:'/etc/dbus-1/system.d/'
)

install_data(
    'conf/provisioning.conf',
    install_dir: '/var/provisioning/',
)