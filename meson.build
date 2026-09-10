project(
  'phosphor-networkd',
  'cpp',
  version: '0.1',
  meson_version: '>=0.58.0',
  default_options: [
    'warning_level=3',
    'cpp_std=c++20',
  ])

default_busname = 'xyz.openbmc_project.Network'
static_ntp_server = 'in.pool.ntp.org'

conf_data = configuration_data()
conf_data.set_quoted('DEFAULT_BUSNAME', default_busname)
conf_data.set_quoted('STATIC_NTP_SERVER', static_ntp_server)
conf_data.set('HAVE_UBOOT_ENV', get_option('uboot-env'))
conf_data.set('IPV4_LINK_LOCAL', get_option('default-link-local-autoconf').contains('ipv4'))
conf_data.set('IPV6_LINK_LOCAL', get_option('default-link-local-autoconf').contains('ipv6'))
conf_data.set('IPV4_IPV6_LINK_LOCAL', get_option('default-link-local-autoconf').contains('true'))
conf_data.set('DISABLE_LINK_LOCAL', get_option('default-link-local-autoconf').contains('false'))
conf_data.set(
  'ENABLE_IPV6_ACCEPT_RA',
  get_option('default-ipv6-accept-ra'))
conf_data.set('SYNC_MAC_FROM_INVENTORY', get_option('sync-mac'))
conf_data.set10('PERSIST_MAC', get_option('persist-mac'))
conf_data.set10('FORCE_SYNC_MAC_FROM_INVENTORY', get_option('force-sync-mac'))
conf_data.set10('AMI_IP_ADVANCED_ROUTING_SUPPORT', get_option('enable-advanced-route'))
conf_data.set10('NCSI_FLOW_CONTROL', get_option('ncsi-flow-control'))
conf_data.set10('NCSI_KEEP_PHY_LINK_UP', get_option('ncsi-keep-phy-link-up'))
conf_data.set10('AMI_NCSI_SUPPORT', get_option('enable-ncsi'))
conf_data.set_quoted('DEFAULT_NCSI_INTERFACE', get_option('default-ncsi-interface'))
if (get_option('enable-system-firewall'))
  conf_data.set10('SYSTEM_FIREWALL_SUPPORT', get_option('enable-system-firewall'))
endif

if (get_option('disable-ping-support'))
  conf_data.set10('DISABLE_PING_FEATURE_SUPPORT', get_option('disable-ping-support'))
endif

conf_data.set10('ENABLE_BOND_SUPPORT', get_option('enable-bond-feature'))
conf_data.set10('PHY_CONFIGURATION_SUPPORT', get_option('enable-phy-configuration'))
conf_data.set10('NSUPDATE_SUPPORT', get_option('enable-nsupdate-feature'))
conf_data.set10('TSIG_SUPPORT', get_option('enable-tsig-feature'))
conf_data.set10('AVAHI_SUPPORT', get_option('enable-avahi-support'))
conf_data.set10('AMI_NCSI_MANUAL_DETECTION', get_option('ncsi-manual-detect'))
conf_data.set10('DOH_SUPPORT', get_option('enable-doh-support'))

tests_opt = get_option('tests')
if tests_opt.enabled()
    sdbusplus_dep = subproject('sdbusplus').get_variable('sdbusplus_dep')
    meson.override_dependency('sdbusplus', sdbusplus_dep)
    phosphor_dbus_interfaces_dep = subproject('phosphor-dbus-interfaces-ami').get_variable('phosphor_dbus_interfaces_dep')
    phosphor_logging_dep = subproject('phosphor-logging').get_variable('phosphor_logging_dep')
    meson.override_dependency('phosphor-logging', phosphor_logging_dep)
else
    sdbusplus_dep = dependency('sdbusplus')
    phosphor_dbus_interfaces_dep = dependency('phosphor-dbus-interfaces')
endif
sdbusplusplus_prog = find_program('sdbus++', native: true)
sdbuspp_gen_meson_prog = find_program('sdbus++-gen-meson', native: true)
sdbusplusplus_depfiles = files()
if sdbusplus_dep.type_name() == 'internal'
  sdbusplusplus_depfiles = subproject('sdbusplus').get_variable('sdbusplusplus_depfiles')
endif

generated_sources = []
generated_others = []
yaml_sources = []
subdir('gen')
subdir('gen/xyz')
networkd_dbus_includes = include_directories('gen')

if tests_opt.enabled()
  # Disable nsupdate feature during test builds: dns::Configuration spawns a
  # background thread whose destructor calls std::thread::~thread() on a
  # running thread, triggering std::terminate() / SIGABRT on teardown.
  conf_data.set10('NSUPDATE_SUPPORT', false)
  add_project_arguments('-DTEST_ENABLED', language: 'cpp')
  add_project_arguments('-Wno-error=unused-variable', language: 'cpp')
  add_project_arguments('-Wno-error=maybe-uninitialized', language: 'cpp')
  add_project_arguments('-Wno-error=sign-compare', language: 'cpp')
  add_project_arguments('-Wno-error=unused-result', language: 'cpp')
  add_project_arguments('-Wno-error=missing-field-initializers', language: 'cpp')
  add_project_arguments('-Wno-error=return-type', language: 'cpp')
  add_project_arguments('-Wno-error=unused-parameter', language: 'cpp')
  add_project_arguments('-Wno-error=parentheses', language: 'cpp')
  add_project_arguments('-Wno-error=pessimizing-move', language: 'cpp')
  add_project_arguments('-Wno-error=ignored-attributes', language: 'cpp')
  add_project_arguments('-Wno-error=type-limits',language: 'cpp')
  add_project_arguments('-Wno-error=catch-value=',language: 'cpp')
  add_project_arguments('-Wno-error=nonnull-compare',language: 'cpp')
  add_project_arguments('-Wno-error=switch', language: 'cpp')
endif

networkd_dbus_deps = [
  phosphor_dbus_interfaces_dep,
  sdbusplus_dep,
]

if tests_opt.enabled()
  networkd_dbus_deps += [phosphor_logging_dep, ]
endif

networkd_dbus_lib = static_library(
  'networkd_dbus',
  generated_sources,
  implicit_include_directories: false,
  include_directories: networkd_dbus_includes,
  dependencies: networkd_dbus_deps)

generated_files_headers = []
foreach s : generated_sources
    foreach f : s.to_list()
        p = f.full_path()
        if p.endswith('.hpp')
            generated_files_headers += f
        endif
    endforeach
endforeach

networkd_dbus_dep = declare_dependency(
  sources: generated_files_headers,
  include_directories: networkd_dbus_includes,
  link_with: networkd_dbus_lib,
  dependencies: networkd_dbus_deps)

subdir('src')

configure_file(
  input: '60-phosphor-networkd-default.network.in',
  output: '60-phosphor-networkd-default.network',
  configuration: {
    'LINK_LOCAL_AUTOCONFIGURATION': get_option('default-link-local-autoconf'),
    'ENABLE_IPV6_ACCEPT_RA': get_option('default-ipv6-accept-ra'),
  },
  install: true,
  install_dir: dependency('systemd').get_variable(
    'systemdutildir') / 'network')

configure_file(
  input: 'xyz.openbmc_project.Network.service.in',
  output: 'xyz.openbmc_project.Network.service',
  configuration: {
    'SYSTEMD_TARGET': 'multi-user.target',
    'DEFAULT_BUSNAME': default_busname,
  },
  install: true,
  install_dir: dependency('systemd').get_variable(
    'systemdsystemunitdir'))

configure_file(
  input: 'xyz.openbmc_project.Network.conf.in',
  output: 'xyz.openbmc_project.Network.conf',
  configuration: {'DEFAULT_BUSNAME': default_busname},
  install: true,
  install_dir: get_option('datadir') / 'dbus-1' / 'system.d')

configure_file(
  input: 'xyz.openbmc_project.GARPControl.service.in',
  output: 'xyz.openbmc_project.GARPControl.service',
  configuration: {
    'SYSTEMD_TARGET': 'multi-user.target',
    'DEFAULT_BUSNAME': default_busname,
  },
  install: true,
  install_dir: dependency('systemd').get_variable(
    pkgconfig: 'systemdsystemunitdir'))

if not get_option('tests').disabled()
  subdir('test')
endif
