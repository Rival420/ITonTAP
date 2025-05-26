---
title: "Hack The Box"
date: 2025-05-25
description: "Writeups and challenges from my Hack The Box adventures."
type: section
draft: false
---

This section is where I drop notes, walkthroughs, and random thoughts while pwning machines and diving into challenges on [Hack The Box](https://hackthebox.com).

### 🧠 My Hack The Box Stats

<div align="center">
  <a href="https://app.hackthebox.com/profile/123067" target="_blank">
    <img src="https://www.hackthebox.com/badge/image/123067" alt="Hack The Box">
  </a>
</div>

### 🛡️ Team TrackHackers

<div align="center">
  <a href="https://app.hackthebox.com/public/teams/overview/5787" target="_blank">
    My team "TrackHackers"
  </a>
</div>

---

<div class="cards-grid">
  <a href="/hackthebox/machines" class="card-link">
    Machines
    <div class="card-desc">Write-ups on the latest (retired) boxes of HackTheBox.</div>
  </a>
  <a href="/hackthebox/challenges" class="card-link">
    Challenges
    <div class="card-desc">Write-ups on challenges for HackTheBox</div>
  </a>
  
<style>
.cards-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); /* Card min width, expand as needed */
  gap: 2rem;
  justify-content: center;
  padding: 2rem 0;
  max-width: 1100px;
  margin: 0 auto;
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
  padding: 2rem;
  text-decoration: none;
  font-weight: bold;
  transition: transform 0.15s, box-shadow 0.15s;
  min-width: 260px;
  max-width: 320px;
  margin: 0 auto;
}
.card-link:hover {
  transform: scale(1.045);
  box-shadow: 0 12px 36px rgba(0,0,0,0.18), 0 1.5px 4px rgba(0,0,0,0.11);
}
.card-desc {
  font-size: 1rem;
  font-weight: 400;
  margin-top: 0.5rem;
  color: #444;
}
/* Mobile: make cards take 95vw for comfort */
@media (max-width: 500px) {
  .card-link {
    min-width: 85vw;
    max-width: 99vw;
    padding: 1.2rem;
  }
}
