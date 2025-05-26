---
title: "Hack The Box"
description: "Brain dumps, walkthroughs, and random pwning logs from my Hack The Box adventures."
---

Welcome to my cozy little infodump corner 🧠💥  
Here you'll find notes, walkthroughs, weird tricks, and other echoes of chaos from my time on [Hack The Box](https://hackthebox.com).

Whether it’s rooted boxes or infuriating challenge puzzles — it all lives here.

---

### 📊 My Stats

<div style="display: flex; flex-wrap: wrap; justify-content: center; gap: 2rem; align-items: center; margin: 2rem 0;">
  <a href="https://app.hackthebox.com/profile/123067" target="_blank">
    <img src="https://www.hackthebox.com/badge/image/123067" alt="HTB Profile Badge" style="max-width: 250px;">
  </a>
  <a href="https://app.hackthebox.com/public/teams/overview/5787" target="_blank">
    <img src="https://www.hackthebox.com/badge/team/image/5787" alt="HTB Team Badge" style="max-width: 250px;">
  </a>
</div>

---

### 📂 Sections

<div class="cards-grid">
  <a href="/hackthebox/machines" class="card-link dark">
    🖥️ Machines
    <div class="card-desc">Walkthroughs of retired boxes I've rooted on HTB.</div>
  </a>
  <a href="/hackthebox/challenges" class="card-link dark">
    🧩 Challenges
    <div class="card-desc">CTF-style brain-twisters from the HTB challenge vault.</div>
  </a>
</div>

<style>
.cards-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 1.5rem;
  justify-content: center;
  padding: 1rem 0;
  max-width: 960px;
  margin: 0 auto 2rem auto;
}
.card-link {
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  align-items: center;
  text-align: center;
  background: #fff;
  color: #222;
  border-radius: 1rem;
  border: 1px solid #e5e7eb;
  box-shadow: 0 8px 32px rgba(0,0,0,0.12), 0 1.5px 4px rgba(0,0,0,0.08);
  padding: 1.5rem;
  text-decoration: none;
  font-weight: bold;
  transition: transform 0.15s, box-shadow 0.15s;
  min-width: 240px;
  max-width: 320px;
}
.card-link:hover {
  transform: scale(1.045);
  box-shadow: 0 12px 36px rgba(0,0,0,0.18), 0 1.5px 4px rgba(0,0,0,0.11);
}
.card-link.dark {
  background: #111827;
  color: #f3f4f6;
  border: 1px solid #374151;
}
.card-desc {
  font-size: 0.95rem;
  font-weight: 400;
  margin-top: 0.5rem;
  color: #9ca3af;
}
/* Responsive tweak for small screens */
@media (max-width: 600px) {
  .cards-grid {
    grid-template-columns: 1fr;
  }
  .card-link {
    min-width: 80vw;
  }
}
</style>
