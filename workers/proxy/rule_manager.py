from aiohttp import web
from .rule_store import RuleStore

_store = RuleStore()


async def post_rule(request):
    data = await request.json()
    rule_id = _store.add_rule(data)
    return web.json_response({"id": rule_id}, status=201)


async def get_rules(request):
    return web.json_response(_store.list_rules())


async def delete_rule(request):
    rule_id = request.match_info["rule_id"]
    if _store.delete_rule(rule_id):
        return web.json_response({"deleted": rule_id})
    return web.json_response({"error": "not found"}, status=404)


def create_app(store=None):
    global _store
    if store:
        _store = store
    app = web.Application()
    app.router.add_post("/rules", post_rule)
    app.router.add_get("/rules", get_rules)
    app.router.add_delete("/rules/{rule_id}", delete_rule)
    return app
