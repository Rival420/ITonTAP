---
title: "Welcome to IT on TAP"
description: "Your hub for tech news, security insights, and the IT on TAP podcast. Choose a section below to get started."
---

Explore our sections below:

<div class="cards-grid">
  <a href="/podcast/" class="card-link">
    🎙️ Podcast
    <div class="card-desc">Tech news, security stories, and relaxed conversations with Pieter and Nick.</div>
  </a>
  <a href="/posts/" class="card-link">
    📝 Blog
    <div class="card-desc">Latest brain dumps and random rants/posts about Cyber Security.</div>
  </a>
  <a href="/hackthebox/" class="card-link">
    📝 HackTheBox
    <div class="card-desc">Content created based on HTB.</div>
  </a>
</div>

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
