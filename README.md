# Customs
This project is VERY MVP and needs a lot of work.  Please understand that the idea is to get the codebase open sourced 
as soon as possible and continually improve it over time. The main reason for this project is to allow the creation of rules 
for container metadata in consul's k/v store.  We felt this was important to allow for dynamic updating and to remove the 
need to add labels and environment variables to containers during creation. There is a good list of things to work on in the 
[road map](ROADMAP.md)


##Description
Small python agent to register docker containers and metadata with Consul.  Customs requires you to create rules which are 
also stored consul defining service specific behavior. These rules define container metadata, tags, and checks. Updates 
to any rule will not require you to restart the customs agent and will happen with in the allotted reconciliation period. 


##Installation
There currently isn't a python package for Customs.  There are plans in the future to supply this. Until this can be provided 
to work with customs you'll have to install [freight-forwarder](https://github.com/tuneoss/freight_forwarder) and modify 
the freight-forwarder.yml file.  To get an understanding of what needs to be changes take a look at the examples in the 
freight-forwarder.yml file. 


## Usage
Due to the lack of documentation here is a very quick overview. Please keep in mind that all communication with the docker 
daemon and consul is done over tcp.  If your require the Socket please submit an issue or PR.

### Rules:
You must create a default rule before attempting to run the agent. Run the following command:

`./bin/customs rules <host> create default`

When you run this command your editor will be opened. Please keep in mind you have to have your editor set in your environment. 
This should live in .bashrc, .profile, .bash_profile, or an equivalent. example: `export EDITOR="subl -w"`

#### Example Rule:
```yaml
# only supports the following four properties.  In addition, either httpcheck or check are able to be picked not both.  
checks:
  check: "(str) The path to the check script to run"
  httpcheck: "(str) An URL to check every interval"
  interval: "(str) The check execution interval"
  ttl: "(str) The TTL for external script check pings"
# Metadata represents what will be populated  in consuls k/v for a specific service or services. Docker container id will 
# always be added to every services metadata.
metadata:
  config:
    domainname: true
    exposed_ports: true
    hostname: true
    image: true
    user: true
    volumes: true
  created: true
  driver: true
  exec_driver: true
  host_config:
    binds: true
    blkio_weight: true
    cap_add: true
    cap_drop: true
    cpu_period: true
    cpu_quota: true
    cpu_shares: true
    cpuset_cpus: true
    cpuset_mems: true
    devices: true
    dns: true
    dns_search: true
    extra_hosts: true
    group_add: true
    links: true
    log_config: true
    memory: true
    memory_swap: true
    memory_swappiness: true
    network_mode: true
    port_bindings: true
    privileged: true
    publish_all_ports: true
    readonly_rootfs: true
    restart_policy: true
    ulimits: true
    volumes_from: true
  id: true
  mounts: true
  network_settings: true
# service_regex will be used to find specific container names.  If there are multiple or no matches default rules are used.
service_regex: .*
# Tags are required to be prefixed by inspect.object=property (based off of docker inspect) or just a string value.
# Tags represent what will be added to the service tags in consul. The customs tag will always be added by default.
tags:
- docker
- inspect.config.labels=com.freight-forwarder.project
- inspect.config.labels=com.freight-forwarder.team
- inspect.config.labels=com.freight-forwarder.type
```

One thing to keep in mind while editing this file is that its not well validated currently, this will be fixed in the future.
In addition, when creating additional rules customs will find your service based on the define service_regex property.


### Catalog
Catalog allows the user to see the current data centers and services registered in consul.


### Agent
The agent command is the agent that will run on each host an register containers with consul.

#### Agent example:
```shell
./bin/customs agent https://dh-alexb01-dev.sea3.office.priv \
    --token=yourtoken \
    --agency-port=8505 \
    --agency-tls=/etc/consul/certs/ \
    --docker-port=2376 \
    --docker-tls=/etc/docker/certs/client/dev/
```

 
##Contributing

TBD

##Contributors
* [abanna](http://github.com/abanna)

## License
See the [LICENSE](LICENSE.md) file for license rights and limitations (MIT).