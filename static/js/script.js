async function postJSON(url, csrfToken, payload) {
    const options = {
        method: "POST",
        headers: {
            "X-CSRFToken": csrfToken,
            "Accept": "application/json"
        }
    };
    if (payload !== undefined) {
        options.headers["Content-Type"] = "application/json";
        options.body = JSON.stringify(payload);
    }

    const response = await fetch(url, options);
    let result;
    try {
        result = await response.json();
    } catch (error) {
        throw new Error("The server returned an unexpected response.");
    }
    if (!response.ok) {
        throw new Error(result.error || "The request could not be completed.");
    }
    return result;
}

function showRequestError(error) {
    alert(error.message || "The request could not be completed. Check your connection and try again.");
}

// ==========================================
// LIKE BUTTONS
// ==========================================
document.querySelectorAll(".like-button").forEach(function (button) {
    button.addEventListener("click", async function () {
        if (button.disabled) return;
        const currentlyLiked = button.getAttribute("aria-pressed") === "true";
        button.disabled = true;
        try {
            const result = await postJSON(
                currentlyLiked ? button.dataset.unlikeUrl : button.dataset.likeUrl,
                button.dataset.csrfToken
            );
            document.querySelectorAll(".like-button").forEach(function (matchingButton) {
                if (matchingButton.dataset.likeUrl !== button.dataset.likeUrl) return;
                matchingButton.classList.toggle("liked", result.liked);
                matchingButton.textContent = result.liked ? "♥" : "♡";
                matchingButton.setAttribute("aria-pressed", String(result.liked));
                const itemLabel = button.dataset.likeLabel || "post";
                matchingButton.setAttribute("aria-label", (result.liked ? "Unlike" : "Like") + " " + itemLabel);
            });
            document.querySelectorAll(".likes-count").forEach(function (count) {
                if (count.dataset.postUrl !== button.dataset.likeUrl) return;
                const label = result.like_count === 1 ? "like" : "likes";
                const text = result.like_count + " " + label;
                const strong = count.querySelector("strong");
                if (strong) strong.textContent = text;
                else count.textContent = text;
            });
        } catch (error) {
            showRequestError(error);
        } finally {
            button.disabled = false;
        }
    });
});

// ==========================================
// COMMENTS SECTION
// ==========================================
function updateCommentCount(post, count) {
    const counter = post.querySelector(".comment-count strong");
    if (counter) {
        counter.textContent = count + (count === 1 ? " comment" : " comments");
    }
}

function createCommentElement(comment, csrfToken) {
    const item = document.createElement("div");
    item.className = "comment-item";
    item.dataset.commentId = comment.id;

    const text = document.createElement("p");
    const userLink = document.createElement("a");
    userLink.className = "comment-username";
    userLink.href = "/users/" + encodeURIComponent(comment.username);

    const username = document.createElement("strong");
    username.textContent = comment.username;
    userLink.appendChild(username);

    const content = document.createElement("span");
    content.textContent = " " + comment.content;

    text.appendChild(userLink);
    text.appendChild(content);
    item.appendChild(text);

    if (comment.delete_url) {
        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "delete-comment-button";
        remove.dataset.deleteUrl = comment.delete_url;
        remove.dataset.csrfToken = csrfToken;
        remove.setAttribute("aria-label", "Delete your comment");
        remove.textContent = "×";
        item.appendChild(remove);
    }
    return item;
}

// Toggle comments section when clicking comment icon or comment count.
function togglePostComments(control) {
    const post = control.closest(".post");
    if (!post) return;
    const section = post.querySelector(".comments-section");
    if (!section) return;

    const isOpen = section.classList.toggle("open");
    const commentButton = post.querySelector(".comment-button");
    control.setAttribute("aria-expanded", String(isOpen));
    if (commentButton) commentButton.setAttribute("aria-expanded", String(isOpen));
    if (isOpen) {
        const input = section.querySelector(".comment-form input");
        if (input) input.focus();
    }
}

document.addEventListener("click", function (event) {
    const control = event.target.closest(".comment-button, .comment-count");
    if (control && control.closest(".post")) togglePostComments(control);
});

document.addEventListener("keydown", function (event) {
    const control = event.target.closest('.comment-count[role="button"]');
    if (!control || event.repeat || (event.key !== "Enter" && event.key !== " ")) return;
    event.preventDefault();
    control.click();
});

// Submit comment
document.querySelectorAll(".comment-form").forEach(function (form) {
    form.addEventListener("submit", async function (event) {
        event.preventDefault();
        const input = form.elements.content;
        const content = input.value.trim();
        if (!content) {
            input.focus();
            return;
        }
        if (content.length > 500) {
            showRequestError(new Error("Comments can be up to 500 characters."));
            return;
        }

        const submitButton = form.querySelector('button[type="submit"]');
        submitButton.disabled = true;
        try {
            const result = await postJSON(form.dataset.commentUrl, form.dataset.csrfToken, { content: content });
            const post = form.closest(".post");
            const section = post.querySelector(".comments-section");
            if (section) section.classList.add("open");
            const commentBtn = post.querySelector(".comment-button");
            if (commentBtn) commentBtn.setAttribute("aria-expanded", "true");

            post.querySelector(".comments-list").appendChild(
                createCommentElement(result, form.dataset.csrfToken)
            );
            updateCommentCount(post, result.comment_count);
            input.value = "";
        } catch (error) {
            showRequestError(error);
        } finally {
            submitButton.disabled = false;
        }
    });
});

// Delete comment
document.addEventListener("click", async function (event) {
    const button = event.target.closest(".delete-comment-button");
    if (!button || button.disabled) return;
    button.disabled = true;
    try {
        const result = await postJSON(button.dataset.deleteUrl, button.dataset.csrfToken);
        const post = button.closest(".post");
        button.closest(".comment-item").remove();
        updateCommentCount(post, result.comment_count);
    } catch (error) {
        showRequestError(error);
        button.disabled = false;
    }
});

// ==========================================
// FOLLOW / UNFOLLOW BUTTONS
// ==========================================
document.addEventListener("click", async function (event) {
    const button = event.target.closest(".follow-button[data-follow-url]");
    if (!button || button.disabled) return;

    const currentlyFollowing = button.getAttribute("aria-pressed") === "true";
    button.disabled = true;

    try {
        const result = await postJSON(
            currentlyFollowing ? button.dataset.unfollowUrl : button.dataset.followUrl,
            button.dataset.csrfToken
        );

        const isFollowing = Boolean(result.following);
        const targetUserId = button.dataset.userId;

        // Synchronize all follow buttons on the page for this user
        if (targetUserId) {
            document.querySelectorAll(`.follow-button[data-user-id="${targetUserId}"]`).forEach(function (btn) {
                btn.textContent = isFollowing ? "Following" : "Follow";
                btn.setAttribute("aria-pressed", String(isFollowing));
                btn.classList.toggle("following", isFollowing);
            });
        } else {
            button.textContent = isFollowing ? "Following" : "Follow";
            button.setAttribute("aria-pressed", String(isFollowing));
            button.classList.toggle("following", isFollowing);
        }

        // Update profile follower/following counts if on a profile page
        const profileEl = document.querySelector("[data-profile-user-id]");
        if (profileEl) {
            const profileUserId = profileEl.dataset.profileUserId;
            if (targetUserId && profileUserId === targetUserId) {
                const followersCount = document.querySelector("[data-followers-count]");
                if (followersCount && result.followers_count !== undefined) {
                    followersCount.textContent = result.followers_count;
                }
                const followingCount = document.querySelector("[data-following-count]");
                if (followingCount && result.target_following_count !== undefined) {
                    followingCount.textContent = result.target_following_count;
                }
            }
        }
    } catch (error) {
        showRequestError(error);
    } finally {
        button.disabled = false;
    }
});

// ==========================================
// SAVE & SHARE BUTTONS
// ==========================================
document.addEventListener("click", async function (event) {
    const button = event.target.closest(".save-button");
    if (!button || button.disabled) return;

    if (button.dataset.saveUrl) {
        button.disabled = true;
        try {
            const result = await postJSON(button.dataset.saveUrl, button.dataset.csrfToken);
            const isSaved = Boolean(result.saved);
            const saveUrl = button.dataset.saveUrl;

            // Synchronize all save buttons on the page for this post
            document.querySelectorAll(`.save-button[data-save-url="${saveUrl}"]`).forEach(function (btn) {
                btn.classList.toggle("saved", isSaved);
                btn.textContent = isSaved ? "▣" : "♧";
                btn.setAttribute("aria-pressed", String(isSaved));
                const itemLabel = saveUrl.includes("/reels/") ? "Reel" : "post";
                btn.setAttribute("aria-label", isSaved ? "Remove saved " + itemLabel : "Save " + itemLabel);
            });

            // If on saved posts page and unsaved, animate removal
            const savedCard = button.closest(".saved-post-card, .saved-reel-card");
            if (savedCard && !isSaved) {
                savedCard.style.transition = "opacity 0.25s ease, transform 0.25s ease";
                savedCard.style.opacity = "0";
                savedCard.style.transform = "scale(0.95)";
                setTimeout(() => {
                    savedCard.remove();
                    const grid = savedCard.closest(".saved-posts-grid");
                    if (grid && grid.querySelectorAll(".saved-post-card, .saved-reel-card").length === 0) {
                        location.reload();
                    }
                }, 260);
            }
        } catch (error) {
            showRequestError(error);
        } finally {
            button.disabled = false;
        }
    } else {
        button.classList.toggle("saved");
        const saved = button.classList.contains("saved");
        button.textContent = saved ? "▣" : "♧";
        button.setAttribute("aria-label", saved ? "Remove saved post" : "Save post");
    }
});

async function copyShareLink(url) {
    try {
        if (navigator.clipboard && window.isSecureContext) {
            try {
                await navigator.clipboard.writeText(url);
                alert("Link copied to clipboard.");
                return;
            } catch (error) {
                // Try the compatibility copy method if clipboard permission is denied.
            }
        }

        const temporaryInput = document.createElement("textarea");
        temporaryInput.value = url;
        temporaryInput.setAttribute("readonly", "");
        temporaryInput.style.position = "fixed";
        temporaryInput.style.left = "-9999px";
        document.body.appendChild(temporaryInput);
        let copied = false;
        try {
            temporaryInput.select();
            copied = document.execCommand("copy");
        } finally {
            temporaryInput.remove();
        }
        if (!copied) throw new Error("Clipboard copy was not available.");
        alert("Link copied to clipboard.");
    } catch (error) {
        alert("Could not copy the link. You can copy it from the address bar.");
    }
}

document.querySelectorAll(".share-button").forEach(function (button) {
    button.addEventListener("click", async function () {
        const post = button.closest(".post");
        const username = post.querySelector(".post-user-details strong").textContent;
        const url = window.location.href;
        if (!navigator.share) {
            await copyShareLink(url);
            return;
        }
        try {
            await navigator.share({
                title: "Instagram Clone",
                text: "Check out this post by " + username,
                url: url
            });
        } catch (error) {
            if (error.name !== "AbortError") await copyShareLink(url);
        }
    });
});

// ==========================================
// POST IMAGE PREVIEW & UPLOAD
// ==========================================
const postImageInput = document.querySelector("#post-image");
if (postImageInput) {
    const preview = document.querySelector("#post-image-preview");
    const removeButton = document.querySelector("#remove-post-image");
    let previewUrl = null;

    function clearPostPreview() {
        if (previewUrl) URL.revokeObjectURL(previewUrl);
        previewUrl = null;
        postImageInput.value = "";
        preview.innerHTML = "<span>Choose a photo to get started</span>";
        removeButton.hidden = true;
    }

    postImageInput.addEventListener("change", function () {
        const file = postImageInput.files[0];
        if (!file) return;
        if (!file.type.startsWith("image/")) {
            alert("Choose a supported image file.");
            clearPostPreview();
            return;
        }
        if (previewUrl) URL.revokeObjectURL(previewUrl);
        previewUrl = URL.createObjectURL(file);
        preview.innerHTML = "";
        const image = document.createElement("img");
        image.src = previewUrl;
        image.alt = "Selected post preview";
        preview.appendChild(image);
        removeButton.hidden = false;
    });

    removeButton.addEventListener("click", clearPostPreview);
}

const captionInput = document.querySelector("#post-caption");
if (captionInput) {
    const counter = document.querySelector("#caption-count");
    captionInput.addEventListener("input", function () {
        counter.textContent = captionInput.value.length;
    });
}

// ==========================================
// NOTIFICATIONS: MARK AS READ ON CLICK
// ==========================================
document.querySelectorAll(".notification-item.unread").forEach(function (item) {
    item.addEventListener("click", async function (event) {
        if (event.target.closest("a") || event.target.closest("button")) return;
        const notifId = item.dataset.notificationId;
        if (!notifId) return;
        const csrfMeta = document.querySelector('meta[name="csrf-token"]');
        const csrfToken = csrfMeta ? csrfMeta.content : "";
        try {
            await postJSON(`/notifications/${notifId}/read`, csrfToken);
            item.classList.remove("unread");
            const badge = document.querySelector(".nav-badge");
            if (badge) {
                const cur = parseInt(badge.textContent, 10) || 1;
                if (cur <= 1) badge.remove();
                else badge.textContent = cur - 1;
            }
        } catch (e) {
            // silent catch
        }
    });
});

// ==========================================
// GRACEFUL IMAGE FALLBACK HANDLER
// ==========================================
function setupImageFallbacks() {
    document.querySelectorAll("img").forEach(function (img) {
        if (img.dataset.fallbackBound) return;
        img.dataset.fallbackBound = "true";
        img.addEventListener("error", function () {
            if (this.dataset.fallbackApplied) return;
            this.dataset.fallbackApplied = "true";
            const isAvatar = (
                this.classList.contains("notification-avatar") ||
                this.classList.contains("explore-author-avatar") ||
                this.classList.contains("saved-author-avatar") ||
                this.classList.contains("post-avatar") ||
                this.classList.contains("profile-avatar") ||
                this.classList.contains("search-user-avatar") ||
                this.classList.contains("edit-avatar") ||
                this.classList.contains("nav-profile-picture") ||
                this.classList.contains("mobile-profile-picture")
            );
            this.src = isAvatar ? "/static/images/default-avatar.svg" : "/static/images/default-post.svg";
        });
    });
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setupImageFallbacks);
} else {
    setupImageFallbacks();
}

// ==========================================
// DIRECT MESSAGES (CHAT, POLLING & MODAL)
// ==========================================
function initDirectMessages() {
    // 1. New Message Modal
    const modal = document.querySelector("#new-message-modal");
    const openModalBtns = document.querySelectorAll(".open-new-modal");
    const closeModalBtn = document.querySelector("#close-modal-btn");
    const userSearchInput = document.querySelector("#modal-user-search");
    const userItems = document.querySelectorAll(".modal-user-item");
    const modalDialog = modal ? modal.querySelector(".modal-dialog") : null;

    if (modal) {
        let modalTrigger = null;

        function closeNewMessageModal() {
            modal.classList.remove("open");
            modal.setAttribute("aria-hidden", "true");
            if (modalTrigger && document.contains(modalTrigger)) modalTrigger.focus();
        }

        openModalBtns.forEach(btn => {
            btn.addEventListener("click", () => {
                modalTrigger = btn;
                modal.classList.add("open");
                modal.setAttribute("aria-hidden", "false");
                if (userSearchInput) {
                    userSearchInput.value = "";
                    userSearchInput.focus();
                    userItems.forEach(item => item.style.display = "");
                } else if (modalDialog) {
                    modalDialog.focus();
                }
            });
        });

        if (closeModalBtn) {
            closeModalBtn.addEventListener("click", closeNewMessageModal);
        }

        modal.addEventListener("click", (e) => {
            if (e.target === modal) closeNewMessageModal();
        });

        modal.addEventListener("keydown", (event) => {
            if (modal.getAttribute("aria-hidden") === "true") return;

            if (event.key === "Escape") {
                event.preventDefault();
                closeNewMessageModal();
                return;
            }

            if (event.key !== "Tab") return;
            const focusable = Array.from(modal.querySelectorAll(
                'button:not([disabled]), input:not([disabled]), [tabindex="0"]'
            )).filter(element => element.getClientRects().length > 0);
            if (focusable.length === 0) {
                event.preventDefault();
                if (modalDialog) modalDialog.focus();
                return;
            }

            const first = focusable[0];
            const last = focusable[focusable.length - 1];
            if (!modal.contains(document.activeElement)) {
                event.preventDefault();
                first.focus();
            } else if (event.shiftKey && document.activeElement === first) {
                event.preventDefault();
                last.focus();
            } else if (!event.shiftKey && document.activeElement === last) {
                event.preventDefault();
                first.focus();
            }
        });

        userItems.forEach(form => {
            form.setAttribute("role", "button");
            form.setAttribute("tabindex", "0");
            form.addEventListener("click", () => form.requestSubmit());
            form.addEventListener("keydown", event => {
                if (event.repeat || (event.key !== "Enter" && event.key !== " ")) return;
                event.preventDefault();
                form.requestSubmit();
            });
        });

        if (userSearchInput) {
            userSearchInput.addEventListener("input", () => {
                const query = userSearchInput.value.trim().toLowerCase();
                userItems.forEach(item => {
                    const u = item.dataset.username || "";
                    const n = item.dataset.name || "";
                    if (u.includes(query) || n.includes(query)) {
                        item.style.display = "";
                    } else {
                        item.style.display = "none";
                    }
                });
            });
        }
    }

    // 2. Chat messaging, auto-scroll, send AJAX & live polling
    const chatBox = document.querySelector(".chat-box");
    const chatForm = document.querySelector("#chat-message-form");
    const chatInput = document.querySelector("#chat-input-field");
    const chatSendBtn = document.querySelector("#chat-send-button");
    const messagesArea = document.querySelector("#chat-messages-area");

    function scrollChatToBottom(smooth = false) {
        if (!messagesArea) return;
        if (smooth) {
            messagesArea.scrollTo({ top: messagesArea.scrollHeight, behavior: "smooth" });
        } else {
            messagesArea.scrollTop = messagesArea.scrollHeight;
        }
    }

    if (chatBox && messagesArea) {
        scrollChatToBottom(false);

        if (chatInput && chatSendBtn) {
            chatInput.addEventListener("input", () => {
                chatSendBtn.disabled = (chatInput.value.trim().length === 0);
            });
        }

        if (chatForm && chatInput) {
            chatForm.addEventListener("submit", async (e) => {
                e.preventDefault();
                const content = chatInput.value.trim();
                if (!content) return;

                const sendUrl = chatForm.dataset.sendUrl;
                const csrfToken = chatForm.dataset.csrfToken;
                chatSendBtn.disabled = true;

                try {
                    const res = await postJSON(sendUrl, csrfToken, { content: content });
                    if (res && res.message) {
                        appendMessageBubble(res.message);
                        chatInput.value = "";
                        chatInput.focus();
                        scrollChatToBottom(true);
                    }
                } catch (err) {
                    showRequestError(err);
                } finally {
                    chatSendBtn.disabled = (chatInput.value.trim().length === 0);
                }
            });
        }

        function appendMessageBubble(msg) {
            if (document.querySelector(`.message-row[data-message-id="${msg.id}"]`)) return;

            const row = document.createElement("div");
            row.className = "message-row " + (msg.is_own ? "sent" : "received");
            row.dataset.messageId = msg.id;

            const bubble = document.createElement("div");
            bubble.className = "message-bubble";
            bubble.title = msg.created_at || "";

            const p = document.createElement("p");
            p.className = "message-content";
            p.textContent = msg.content;

            const time = document.createElement("span");
            time.className = "message-timestamp";
            let timeStr = "";
            if (msg.created_at) {
                const parts = msg.created_at.split("·");
                timeStr = parts.length > 1 ? parts[1].trim() : msg.created_at;
            }
            time.textContent = timeStr;

            bubble.appendChild(p);
            bubble.appendChild(time);
            row.appendChild(bubble);
            messagesArea.appendChild(row);
        }

        // Live polling every 3 seconds for new incoming messages
        const convId = chatBox.dataset.conversationId;
        if (convId) {
            let lastMessageId = 0;
            const rows = messagesArea.querySelectorAll(".message-row[data-message-id]");
            if (rows.length > 0) {
                lastMessageId = parseInt(rows[rows.length - 1].dataset.messageId, 10) || 0;
            }

            setInterval(async () => {
                try {
                    const res = await fetch(`/messages/${convId}/poll?after=${lastMessageId}`);
                    if (!res.ok) return;
                    const data = await res.json();
                    if (data && data.messages && data.messages.length > 0) {
                        data.messages.forEach(msg => {
                            appendMessageBubble(msg);
                            if (msg.id > lastMessageId) lastMessageId = msg.id;
                        });
                        scrollChatToBottom(true);
                    }
                } catch (err) {
                    // silent catch for poll
                }
            }, 3000);
        }
    }
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initDirectMessages);
} else {
    initDirectMessages();
}

// ==========================================
// REELS VIDEO CONTROLS & UPLOAD PREVIEW
// ==========================================
function initReels() {
    document.querySelectorAll(".reel-card").forEach(function (card) {
        const video = card.querySelector(".reel-video");
        const playButton = card.querySelector(".reel-play-toggle");
        const muteButton = card.querySelector(".reel-mute-toggle");
        if (!video) return;

        function updatePlayButton() {
            const isPlaying = !video.paused && !video.ended;
            if (playButton) {
                playButton.textContent = isPlaying ? "Pause" : "Play";
                playButton.setAttribute("aria-label", isPlaying ? "Pause video" : "Play video");
                playButton.setAttribute("aria-pressed", String(isPlaying));
            }
        }

        function updateMuteButton() {
            if (muteButton) {
                muteButton.textContent = video.muted ? "Unmute" : "Mute";
                muteButton.setAttribute("aria-label", video.muted ? "Unmute video" : "Mute video");
                muteButton.setAttribute("aria-pressed", String(!video.muted));
            }
        }

        if (playButton) {
            playButton.addEventListener("click", function () {
                if (video.paused) video.play().catch(() => {});
                else video.pause();
            });
        }
        if (muteButton) {
            muteButton.addEventListener("click", function () {
                video.muted = !video.muted;
                updateMuteButton();
            });
        }
        video.addEventListener("play", updatePlayButton);
        video.addEventListener("pause", updatePlayButton);
        video.addEventListener("ended", updatePlayButton);
        video.addEventListener("volumechange", updateMuteButton);
        updatePlayButton();
        updateMuteButton();
    });

    document.querySelectorAll("[data-reel-nav]").forEach(function (button) {
        button.addEventListener("click", function () {
            const cards = Array.from(document.querySelectorAll(".reel-card"));
            const currentIndex = cards.indexOf(button.closest(".reel-card"));
            const direction = button.dataset.reelNav === "next" ? 1 : -1;
            const nextCard = cards[currentIndex + direction];
            if (nextCard) nextCard.scrollIntoView({ behavior: "smooth", block: "center" });
        });
    });

    if ("IntersectionObserver" in window) {
        const videoObserver = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                const video = entry.target;
                if (entry.isIntersecting && entry.intersectionRatio >= 0.65) {
                    video.play().catch(() => {});
                } else {
                    video.pause();
                }
            });
        }, { threshold: [0, 0.65, 1] });
        document.querySelectorAll(".reel-card .reel-video").forEach(video => videoObserver.observe(video));
    }

    const input = document.querySelector("#reel-video-input");
    const preview = document.querySelector("#reel-video-preview");
    if (input && preview) {
        let previewUrl = null;
        input.addEventListener("change", function () {
            const file = input.files && input.files[0];
            if (previewUrl) URL.revokeObjectURL(previewUrl);
            previewUrl = null;
            if (!file) {
                preview.removeAttribute("src");
                preview.hidden = true;
                return;
            }
            const allowedTypes = ["video/mp4", "video/webm"];
            if (!allowedTypes.includes(file.type)) {
                alert("Choose a valid MP4 or WebM video.");
                input.value = "";
                preview.hidden = true;
                return;
            }
            previewUrl = URL.createObjectURL(file);
            preview.src = previewUrl;
            preview.hidden = false;
            preview.load();
        });
    }
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initReels);
} else {
    initReels();
}
