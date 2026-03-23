# CDItemVisibilityPatcher

A simple patcher to change item visibility in Crimson Desert.

## Overview

This tool lets you edit XML files to control the visibility of equipment on your character in Crimson Desert. It's especially useful if you want to hide certain items—like shields, bows, etc.—from your character's back while still making them visible when in use.

## Features

- Hide shields, bows, and more from your character's back
- Equipment remains visible during active use
- Fast XML patching for quick changes

## Usage

1. Edit the relevant XML configuration file to trigger item visibility changes for your character.
2. Apply the patch.
3. Launch Crimson Desert and enjoy your custom equipment visibility.

> **Note:** Items hidden using this tool will still appear when used in-game.

## Example

```xml
<!-- Example entry to hide a shield -->
<Item type="Shield" visibility="hidden"/>
```

## Requirements

- Crimson Desert game files
- Ability to edit XML configuration files

## Troubleshooting

If items do not hide or appear as expected, double-check your XML edits for correctness and ensure the patch is applied to the right game directory.

## Contributing

Feel free to open issues or submit pull requests to improve this tool!