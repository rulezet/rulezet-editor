"""rulezet-editor serve: standalone editor server (playground + editor API)."""
import argparse
import os


def main(argv=None):
    parser = argparse.ArgumentParser(prog='rulezet-editor')
    sub = parser.add_subparsers(dest='command', required=True)
    serve = sub.add_parser('serve', help='run the standalone editor server')
    serve.add_argument('--host', default=os.environ.get('HOST', '127.0.0.1'))
    serve.add_argument('--port', type=int, default=int(os.environ.get('PORT', 5174)))
    serve.add_argument('--rulezet-url', default=os.environ.get('RULEZET_URL', 'https://rulezet.org'),
                       help='Rulezet instance for rule lookup and formats not validated locally')
    serve.add_argument('--api-key', default=os.environ.get('RULEZET_API_KEY'))
    serve.add_argument('--offline', action='store_true', help='local validation only, no Rulezet')
    serve.add_argument('--debug', action='store_true')
    args = parser.parse_args(argv)

    from .web import create_app
    app = create_app(rulezet_url=None if args.offline else args.rulezet_url, api_key=args.api_key)
    backend = app.config['EDITOR_BACKEND']
    print(f'\n  Editor:   http://{args.host}:{args.port}/')
    print(f'  API:      http://{args.host}:{args.port}/editor-api/')
    print(f'  Local:    {", ".join(f for b in backend.backends[:1] for f in b.formats()) or "none (pip install yara-python)"}')
    print(f'  Rulezet:  {"off" if args.offline else args.rulezet_url}\n')
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
