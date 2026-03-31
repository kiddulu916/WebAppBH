from aiohttp import web
from .callback_store import CallbackStore

_store = CallbackStore()


async def register_callback(request):
    data = await request.json()
    cb_id = _store.register(protocols=data.get("protocols"))
    return web.json_response({"id": cb_id}, status=201)


async def poll_callback(request):
    cb_id = request.match_info["cb_id"]
    cb = _store.get(cb_id)
    if cb is None:
        return web.json_response({"error": "not found"}, status=404)
    return web.json_response(cb)


async def record_interaction(request):
    cb_id = request.match_info["cb_id"]
    data = await request.json()
    if _store.record_interaction(cb_id, data):
        return web.json_response({"recorded": True})
    return web.json_response({"error": "not found"}, status=404)


async def delete_callback(request):
    cb_id = request.match_info["cb_id"]
    if _store.cleanup(cb_id):
        return web.json_response({"deleted": cb_id})
    return web.json_response({"error": "not found"}, status=404)


def create_app(store=None):
    global _store
    if store:
        _store = store
    app = web.Application()
    app.router.add_post("/callbacks", register_callback)
    app.router.add_get("/callbacks/{cb_id}", poll_callback)
    app.router.add_post("/callbacks/{cb_id}/interaction", record_interaction)
    app.router.add_delete("/callbacks/{cb_id}", delete_callback)
    return app
