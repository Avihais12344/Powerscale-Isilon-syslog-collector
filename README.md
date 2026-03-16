# Powerscale-Isilon-syslog-collector
Otel Collector for syslog messages

It gets isilno powerscale syslog messages and output them with nice parsing.

## How to run?

```bash
podman compose up -d
```

If using docker:

```bash
docker-compose up -d
```

I have worked and tested it using docker.

## Known errors

### Permission denied

In case or the error:

```
Error: cannot start pipelines: failed to start "file" exporter: open /mnt/logs/logs.jsonl: permission denied
```

Please run:

```bash
chmod -R 777 logs/
```

So there will be permissions to the files.
