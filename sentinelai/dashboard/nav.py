"""Page registry so one page can open another with a pre-selected item."""
from __future__ import annotations

import streamlit as st

PAGES: dict = {}


def go(page: str, **state) -> None:
    for key, value in state.items():
        st.session_state[key] = value
    target = PAGES.get(page)
    if target is not None:
        st.switch_page(target)
