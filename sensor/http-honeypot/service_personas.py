"""Whole-port personas: every request on these ports gets one product's API instead of the
path-routed web personas. An unauthenticated Docker Engine API (2375) and an open
Elasticsearch 7 node (9200), with believable state so attack scripts reach their payload."""
import json
import re
import secrets

from aiohttp import web

from personas import text

# ---------------------------------------------------------------- Docker Engine API

DOCKER_HEADERS = {"Server": "Docker/20.10.21 (linux)", "Api-Version": "1.41", "Docker-Experimental": "false",
                  "Ostype": "linux"}
API_PREFIX = re.compile(r"^/v[\d.]+(?=/)")
CONTAINERS = [
    {"Id": "4f1c9b2e8d0a77e3c1b5d6a9f8e7c6b5a4d3c2b1a0f9e8d7c6b5a4d3c2b1a0f9", "Names": ["/portal-web"],
     "Image": "nginx:1.23", "Command": "/docker-entrypoint.sh nginx -g 'daemon off;'", "State": "running",
     "Status": "Up 6 weeks", "Ports": [{"PrivatePort": 80, "PublicPort": 80, "Type": "tcp"}]},
    {"Id": "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b", "Names": ["/portal-db"],
     "Image": "postgres:13", "Command": "docker-entrypoint.sh postgres", "State": "running",
     "Status": "Up 6 weeks", "Ports": [{"PrivatePort": 5432, "Type": "tcp"}]},
]
RAW_STREAM = "application/vnd.docker.raw-stream"


def _djson(obj, status=200) -> web.Response:
    return web.json_response(obj, status=status, headers=DOCKER_HEADERS)


def _empty(status=200, ctype=None) -> web.Response:
    return web.Response(status=status, body=b"", content_type=ctype, headers=DOCKER_HEADERS)


def docker_api(req: web.Request, body: bytes) -> web.Response:
    path = API_PREFIX.sub("", req.raw_path.split("?")[0])
    post = req.method == "POST"
    if path == "/_ping":
        return web.Response(text="OK", headers=DOCKER_HEADERS)
    if path == "/version":
        return _djson({"Version": "20.10.21", "ApiVersion": "1.41", "MinAPIVersion": "1.12", "GitCommit": "3056208",
                       "GoVersion": "go1.18.7", "Os": "linux", "Arch": "amd64", "KernelVersion": "5.15.0-122-generic",
                       "BuildTime": "2022-10-25T18:00:04.000000000+00:00"})
    if path == "/info":
        return _djson({"ID": "QX4M:7HZD:QFBN:5XKA:Y2MV:CL3P:LNTE:S4WJ:2V7K:RZPA:H6UF:NDQB", "Containers": 2,
                       "ContainersRunning": 2, "Images": 6, "Driver": "overlay2", "NCPU": 8, "MemTotal": 16777216000,
                       "OperatingSystem": "Ubuntu 22.04.5 LTS", "OSType": "linux", "Architecture": "x86_64",
                       "KernelVersion": "5.15.0-122-generic", "Name": "web-prod-02", "ServerVersion": "20.10.21",
                       "DockerRootDir": "/var/lib/docker",
                       "SecurityOptions": ["name=apparmor", "name=seccomp,profile=default"]})
    if path == "/containers/json":
        return _djson(CONTAINERS)
    if path == "/images/json":
        return _djson([{"Id": "sha256:" + "a1" * 32, "RepoTags": ["nginx:1.23"], "Size": 142145851},
                       {"Id": "sha256:" + "b2" * 32, "RepoTags": ["postgres:13"], "Size": 373806394}])
    if post and path == "/containers/create":
        return _djson({"Id": secrets.token_hex(32), "Warnings": []}, 201)
    if post and re.fullmatch(r"/containers/[\w.-]+/exec", path):
        return _djson({"Id": secrets.token_hex(32)}, 201)
    if post and re.fullmatch(r"/exec/\w+/start", path):
        return _empty(ctype=RAW_STREAM)
    if re.fullmatch(r"/exec/\w+/json", path):
        return _djson({"ExitCode": 0, "Running": False, "Pid": 0})
    if post and re.fullmatch(r"/containers/[\w.-]+/(start|stop|kill|restart|pause|unpause)", path):
        return _empty(204)
    if post and re.fullmatch(r"/containers/[\w.-]+/wait", path):
        return _djson({"StatusCode": 0})
    if re.fullmatch(r"/containers/[\w.-]+/(logs|attach)", path):
        return _empty(ctype=RAW_STREAM)
    if req.method == "DELETE" and path.startswith("/containers/"):
        return _empty(204)
    if post and path == "/images/create":
        image, tag = req.query.get("fromImage", "image")[:200], req.query.get("tag", "latest")[:64]
        lines = [{"status": f"Pulling from {image}", "id": tag},
                 {"status": "Pulling fs layer", "id": "a2abf6c4d29d"},
                 {"status": "Pull complete", "id": "a2abf6c4d29d"},
                 {"status": f"Digest: sha256:{secrets.token_hex(32)}"},
                 {"status": f"Status: Downloaded newer image for {image}:{tag}"}]
        return web.Response(text="\r\n".join(json.dumps(x) for x in lines) + "\r\n",
                            content_type="application/json", headers=DOCKER_HEADERS)
    return _djson({"message": "page not found"}, 404)


# ---------------------------------------------------------------- Elasticsearch

ES_CLUSTER = {"name": "es-node-1", "cluster_name": "portal-search", "cluster_uuid": "kX2pQ8nZRS2v7Lr1mT4yWg",
              "version": {"number": "7.10.2", "build_flavor": "default", "build_type": "deb",
                          "build_hash": "747e1cc71def077253878a59143c1f785afa92b9",
                          "build_date": "2021-01-13T00:42:12.435326Z", "build_snapshot": False,
                          "lucene_version": "8.7.0", "minimum_wire_compatibility_version": "6.8.0",
                          "minimum_index_compatibility_version": "6.0.0-beta1"},
              "tagline": "You Know, for Search"}
ES_INDICES = (
    "health status index          uuid                   pri rep docs.count docs.deleted store.size pri.store.size\n"
    "yellow open   customers      Q3xvLb0yTqW1n8m2Kc4fZg   1   1     184213          912     96.4mb         96.4mb\n"
    "yellow open   orders-2026.10 hR7dM2pNSkO6vX1aL9yUqw   1   1     731004            0    402.1mb        402.1mb\n"
    "yellow open   users          b8VnT0kWQeG3sZ5jF2xHcA   1   1      12877           41      6.2mb          6.2mb\n"
    "green  open   .kibana_1      Zp1Lq7RsTyU4wX0vN3mB8e   1   0         58            2    104.7kb        104.7kb\n"
)
# Obviously fictional records on reserved example domains: enough to look like a live customer index.
ES_HITS = [{"_index": "customers", "_id": "1001", "_score": 1.0,
            "_source": {"name": "Jordan Ellis", "email": "j.ellis@example.com", "tier": "gold"}},
           {"_index": "customers", "_id": "1002", "_score": 1.0,
            "_source": {"name": "Sam Ortega", "email": "sam.o@example.net", "tier": "standard"}}]


def _ejson(obj, status=200) -> web.Response:
    return web.json_response(obj, status=status)


def elasticsearch(req: web.Request, body: bytes) -> web.Response:
    path = req.raw_path.split("?")[0].rstrip("/") or "/"
    m = req.method
    if path == "/":
        return _ejson(ES_CLUSTER)
    if path.startswith("/_cat/indices"):
        return text(ES_INDICES)
    if path in ("/_cat/health", "/_cluster/health"):
        return _ejson({"cluster_name": "portal-search", "status": "yellow", "number_of_nodes": 1,
                       "active_primary_shards": 4, "unassigned_shards": 3})
    if path.startswith("/_nodes"):
        return _ejson({"_nodes": {"total": 1, "successful": 1, "failed": 0}, "cluster_name": "portal-search",
                       "nodes": {"Wq3xLb0y": {"name": "es-node-1", "version": "7.10.2", "os": {"name": "Linux"}}}})
    if path.endswith("/_search"):
        return _ejson({"took": 4, "timed_out": False,
                       "_shards": {"total": 4, "successful": 4, "skipped": 0, "failed": 0},
                       "hits": {"total": {"value": 184213, "relation": "eq"}, "max_score": 1.0, "hits": ES_HITS}})
    if m == "DELETE":
        return _ejson({"acknowledged": True})
    if m in ("PUT", "POST") and re.fullmatch(r"/[\w.-]+/_doc(/[\w.-]+)?", path):
        return _ejson({"_index": path.split("/")[1], "_id": secrets.token_hex(10), "_version": 1, "result": "created",
                       "_shards": {"total": 2, "successful": 1, "failed": 0}}, 201)
    if m == "PUT" and re.fullmatch(r"/[\w.-]+", path):
        return _ejson({"acknowledged": True, "shards_acknowledged": True, "index": path[1:]})
    return _ejson({"error": {"root_cause": [{"type": "index_not_found_exception", "reason": "no such index"}],
                             "type": "index_not_found_exception", "reason": "no such index"}, "status": 404}, 404)


PORT_PERSONAS = {"docker": docker_api, "elasticsearch": elasticsearch}
