"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const menuButton = document.querySelector(".menu-toggle");
  const mobileMenu = document.querySelector("#mobile-menu");
  if (menuButton && mobileMenu) {
    menuButton.addEventListener("click", () => {
      const isExpanded = menuButton.getAttribute("aria-expanded") === "true";
      menuButton.setAttribute("aria-expanded", String(!isExpanded));
      mobileMenu.hidden = isExpanded;
    });
  }

  document.querySelectorAll("[data-confirm-assessment]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      const acknowledgement = form.querySelector('input[name="acknowledged"]');
      const confirmation = form.querySelector('input[name="confirmation"]');
      if (!acknowledgement?.checked || confirmation?.value !== "yes") {
        return;
      }
      if (!window.confirm("Start the assessment using the exact validated scope shown on this page?")) {
        event.preventDefault();
      }
    });
  });
});
