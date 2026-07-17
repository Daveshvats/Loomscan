"""Quick test: does opentui render properly in our terminal?"""
import asyncio
import opentui
from opentui import (
    render, Box, Text, Signal, component, use_keyboard, use_renderer,
    Bold
)

count = Signal(0, name="count")

@component
def App():
    return Box(
        Box(
            Text(Bold("LoomScan"), fg="#00ff00"),
            Text("Static + Test + Constraint Analysis", fg="#888888"),
            flex_direction="column",
            align_items="center",
            gap=0,
            padding=(1, 2),
        ),
        Box(
            Text(lambda: f"  Count: {count()}  ", fg="#ffffff"),
            padding=(1, 2),
            border=True,
            border_color="#00ff00",
        ),
        Box(
            Text("  Press +/- to change, q to quit  ", fg="#666666"),
            padding=(0, 2),
        ),
        flex_direction="column",
        align_items="center",
        justify_content="center",
        gap=1,
        padding=2,
    )

def on_key(event):
    if event.name == "q":
        r = use_renderer()
        if r:
            r.stop()
    elif event.name in ("+", "="):
        count.add(1)
    elif event.name == "-":
        count.add(-1)

async def main():
    use_keyboard(on_key)
    await render(App)

if __name__ == "__main__":
    asyncio.run(main())
