# Diagrams

PlantUML sources live next to their rendered artifacts:

- `*.puml`: editable source
- `*.png`: README-friendly rendered image
- `*.svg`: scalable rendered image for documentation reuse

Regenerate after editing a diagram source:

```bash
plantuml -tpng docs/diagrams/*.puml
plantuml -tsvg docs/diagrams/*.puml
```

Do not edit rendered PNG or SVG files by hand.
