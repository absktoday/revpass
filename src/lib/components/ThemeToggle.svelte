<script lang="ts">
  import { userPrefersMode } from "mode-watcher";
  import { Button } from "$lib/components/ui/button";
  import { Sun, Moon, Monitor } from "@lucide/svelte";

  function cycleTheme() {
    if (userPrefersMode.current === "light") {
      userPrefersMode.current = "dark";
    } else if (userPrefersMode.current === "dark") {
      userPrefersMode.current = "system";
    } else {
      userPrefersMode.current = "light";
    }
  }
</script>

<Button 
  variant="outline" 
  size="icon" 
  onclick={cycleTheme} 
  class="relative overflow-hidden w-9 h-9 border-border bg-card hover:bg-muted/50 rounded-xl transition-all duration-300"
  title="Theme: {userPrefersMode.current === 'system' ? 'System' : userPrefersMode.current === 'dark' ? 'Dark' : 'Light'}"
>
  {#if userPrefersMode.current === "light"}
    <Sun class="w-4.5 h-4.5 text-amber-500 transition-all scale-100 rotate-0" />
  {:else if userPrefersMode.current === "dark"}
    <Moon class="w-4.5 h-4.5 text-indigo-400 transition-all scale-100 rotate-0" />
  {:else}
    <Monitor class="w-4.5 h-4.5 text-muted-foreground transition-all scale-100 rotate-0" />
  {/if}
</Button>
