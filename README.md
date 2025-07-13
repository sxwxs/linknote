# LinkNote

A web-based bookmark manager that allows you to save and organize links with tags and markdown descriptions.

## Features

- Save links with titles, tags, and markdown descriptions
- Advanced search with support for quoted phrases
- Filter notes by title, tags, description, or author
- Sort notes by title (default), creation time, or link
- Support for both web server and static file modes
- Flexible data storage (JSON or JS files)
- Custom save locations
- Command-line interface

## Installation

```bash
pip install .
```

## Usage

### Command Line Interface

1. Start the web server:
```bash
linknote start  # Starts server at http://127.0.0.1:5000
```

Optional parameters:
- `--host` or `-h`: Set host address (default: 127.0.0.1)
- `--port` or `-p`: Set port number (default: 5000)

2. Open data directory:
```bash
linknote data  # Opens the default data directory
```

### Web Interface

1. Adding Notes:
   - Enter author name (saved for future use)
   - Use template URLs with parameters (e.g., `https://example.com/{param}`)
   - Click "New Note" button
   - Fill in title (required) and link (required)
   - Add optional tags (comma-separated)
   - Add optional description (supports markdown)

2. Searching/Filtering:
   - Type in the search box to filter notes
   - Use quotes for exact phrases (e.g., `"example phrase"`)
   - Space-separated terms are treated as separate keywords
   - Searches through titles, tags, descriptions, and authors
   - Results update in real-time

3. Managing Notes:
   - Duplicate existing notes
   - Sort notes by title, creation time, or link
   - Template URLs: Create parameterized links
     - Use `{paramName}` in URLs (e.g., `https://api.example.com/{version}/{endpoint}`)
     - Input fields automatically created for each parameter
     - Real-time URL preview as you type

4. Saving Notes:
   - Click "Save All" to save changes
   - Choose between default location or custom path
   - Supports both .js and .json file formats

### Note Fields

- Title (required): Display name, used for search and sorting
- Link (required): URL or template URL
- Author: Automatically saved and used as default for new notes
- Tags: Comma-separated labels for organization
- Description: Supports markdown formatting
- Timestamps: 
  - Creation time: Set when note is first created
  - Modification time: Updated on each edit

### Data Storage

- Windows: `%APPDATA%/linknote/data.js`
- Linux: `~/.local/share/linknote/data.js`
- Custom: Choose any location and format (.js or .json)

### Static Mode

You can use LinkNote without a server by:
1. Copy the static files (`index.html`, `style.css`, `script.js`, `data.js`)
2. Open `index.html` in a browser
3. Data will be loaded from `data.js`

Note: In static mode, saving changes is disabled

### Markdown Support

Description field supports basic markdown:
- Links: `[text](url)`
- Bold: `**text**`
- Italic: `*text*`
- Code: `` `code` ``

## Deployment in Public Networks

**Warning:** This application has an experimental authentication feature that is not recommended for production use. For public-facing deployments, it is strongly recommended to use a reverse proxy with a robust authentication mechanism, such as HTTP Basic Authentication provided by servers like Nginx. This ensures that your LinkNote instance is secure.

## Development

### Project Structure

```
linknote/
├── linknote/
│   ├── __init__.py
│   ├── cli.py         # Command-line interface
│   ├── server.py      # Flask backend
│   └── static/        # Frontend files
│       ├── index.html
│       ├── style.css
│       ├── script.js
│       └── data.js
└── setup.py
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License
