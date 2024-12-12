# MariaDB Enforce Environment Variable - MARIADB_USER

This Policy ensures MARIADB_USER environment variable are in place when using the official container images from Docker Hub.
MARIADB_USER: The MARIADB_USER environment variable sets up a superuser with the same name.


If you encounter a violation, ensure the MARIADB_USER environment variables is set.
For futher information about the MariaDB Docker container, check here: https://hub.docker.com/_/mariadb


# Settings
```yaml
  settings:
    parameters:
      - name: exclude_namespaces
        type: array
        required: false
        value:
      - name: exclude_label_key
        type: string
        required: false
        value:
      - name: exclude_label_value
        type: string
        required: false
        value:
```

# Resources
Policy applies to resources kinds:
`Deployment`, `Job`, `ReplicationController`, `ReplicaSet`, `DaemonSet`, `StatefulSet`, `CronJob`