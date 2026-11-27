import hashlib
from pathlib import Path
from flask import request


def install_asset_revisions(app):
    revisions={}
    roots={'static':app.static_folder}
    roots.update({name+'.static':bp.static_folder for name,bp in app.blueprints.items() if bp.static_folder})
    for endpoint,folder in roots.items():
        root=Path(folder)
        for path in root.rglob('*'):
            if path.is_file() and path.suffix in {'.css','.js'}:
                revisions[(endpoint,path.relative_to(root).as_posix())]=hashlib.sha256(path.read_bytes()).hexdigest()[:16]

    @app.url_defaults
    def asset_revision(endpoint,values):
        revision=revisions.get((endpoint,values.get('filename')))
        if revision:
            values.pop('v',None)
            values['rev']=revision

    def cache_revision(response):
        filename = (request.view_args or {}).get('filename')
        version = revisions.get((request.endpoint, filename))
        if response.status_code in (200, 304) and version and request.args.get('rev') == version:
            response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
        return response

    app.after_request_funcs.setdefault(None, []).insert(0, cache_revision)
