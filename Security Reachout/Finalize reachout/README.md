Updates the DM, comments/tags/prioritizes the Tines case, adds a color-coded Case Note with the final answer (green = confirmed, red = denied, blue = no response; created once per reachout via `note_created`), and replies in the alert thread. Triggered by a click, and every minute to time out unanswered reachouts.

When "Slack interactivity" forwards a **Close Case** click (`x-close-case-id`), it sets that Tines case's status to `closed` (skipped if already closed), comments who closed it, and replies in the Slack message's thread.
