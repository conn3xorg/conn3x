# Converted from the Ansible role mixed by conn3x convert ansible.
# Search for TODO(convert) to find what still needs a person.

# TODO(convert): dependencies (meta/main.yml line 2) runs the roles common, geerlingguy.firewall first; convert a playbook that runs this role, with -out, and they're converted and called before it.
# TODO(convert): argument_specs (meta/main.yml line 5) checks the role's arguments, which the converter doesn't carry over to variable types and validation yet.

circuit "mixed" {
  hosts = var.hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  # TODO(convert): Task "Pick the OS tasks" (tasks/main.yml line 1) includes a file per family, and for Debian hosts it imports Debian.yml, which wasn't found beside tasks/main.yml.
  #   - name: Pick the OS tasks
  #     include_tasks: "{{ ansible_os_family }}.yml"

  # TODO(convert): Task "Only on Debian" (tasks/main.yml line 4) sets when on import_tasks, which applies it to every task it imports; the converter can't translate that yet.
  #   - name: Only on Debian
  #     import_tasks: debian.yml
  #     when: ansible_os_family == "Debian"

  # TODO(convert): Task "Missing file" (tasks/main.yml line 8) imports nowhere.yml, which wasn't found beside tasks/main.yml.
  #   - name: Missing file
  #     import_tasks: nowhere.yml

  # TODO(convert): Task "Back again" (tasks/loop.yml line 1) imports tasks/loop.yml, which is already being imported, so it would never finish.
  #   - name: Back again
  #     import_tasks: loop.yml

  # TODO(convert): Task "Another role" (tasks/main.yml line 14) uses include_role, which runs another role here; the converter only calls roles run from a play's own task lists, with -out, so convert that role with -role and call its circuit as a module.
  #   - name: Another role
  #     include_role:
  #       name: common

  # TODO(convert): Task "As root" (tasks/main.yml line 18) sets become, which in a circuit the ssh block decides for every step; take it off the task, and log in as root or set ssh_become.
  #   - name: As root
  #     package:
  #       name: vim
  #     become: true

  # TODO(convert): Task "Mode from a default" (tasks/main.yml line 23) mode refers to the role default "mixed_mode", and the converter keeps a default as a variable only where Conn3x uses its value exactly as Ansible does, whatever it is set to; here it would have to check the value first.
  #   - name: Mode from a default
  #     copy:
  #       dest: /etc/mixed.txt
  #       content: "hi\n"
  #       mode: "{{ mixed_mode }}"

  # TODO(convert): Task "Path from a default" (tasks/main.yml line 29) path refers to the role default "mixed_conf_dir", and the converter keeps a default as a variable only where Conn3x uses its value exactly as Ansible does, whatever it is set to; here it would have to check the value first.
  #   - name: Path from a default
  #     file:
  #       path: "{{ mixed_conf_dir }}"
  #       state: directory

  # TODO(convert): Task "Templated config" (tasks/main.yml line 34) renders a template that uses Jinja statements or comments, {% %} or {# #}; rewrite it in templatefile syntax (${var}, %{ if }) and use a template step.
  #   - name: Templated config
  #     template:
  #       src: logic.conf.j2
  #       dest: /etc/mixed/logic.conf

  # TODO(convert): Task "Outside the role" (tasks/main.yml line 39) ../../etc/passwd is outside the role's files/.
  #   - name: Outside the role
  #     copy:
  #       src: ../../etc/passwd
  #       dest: /tmp/passwd
}
